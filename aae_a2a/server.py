"""Supplier agent: an A2A server that declares the AAE extension in its Agent
Card and verifies an AAE before it performs a gated skill.

Profile mapping (spec sections 5-8):
  message 1  SendMessage with metadata[URI] = {"aae", "ancestor_jws"?} and one
             data Part {"skill", "transaction"}  ->  section 5 steps 1-3, then
             Task in TASK_STATE_AUTH_REQUIRED carrying the step-4 challenge
  message 2  SendMessage on that task with metadata[URI] = {"challenge_response"}
             ->  section 5 steps 1-9. Accepted: the skill runs and the task ends in
             its outcome, TASK_STATE_COMPLETED or TASK_STATE_FAILED, with the
             ACCEPT receipt in Task.metadata[URI] either way. Rejected:
             TASK_STATE_REJECTED with the failing step, and the skill never runs.
             Both results carry request_digest (spec section 8.5).
Protocol violations (extension not activated, metadata missing) are JSON-RPC
errors and create no task.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from google.protobuf import json_format
from starlette.applications import Starlette

from a2a.extensions.common import find_extension_by_uri
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Message,
    Part,
    SendMessageRequest,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import ExtensionSupportRequiredError, InvalidParamsError

from .challenge import ChallengeError, SubjectBinding, utc_now
from .constants import A2A_EXTENSIONS_HEADER, AAE_DRAFT, EXTENSION_URI, MAX_ANCESTORS
from .didres import LocalDidResolver
from .digest import request_digest
from .verifier import STEP_NAMES, AaeVerifier, Reject

log = logging.getLogger("aae_a2a.supplier")

RPC_PATH = "/a2a/jsonrpc"


# --- request decoding ------------------------------------------------------------

def normalize_numbers(v):
    """google.protobuf.Value carries every number as a double. Map integral
    doubles within +/-2^53 back to integers (spec section 6.3)."""
    if isinstance(v, float) and v.is_integer() and abs(v) <= 2 ** 53:
        return int(v)
    if isinstance(v, dict):
        return {k: normalize_numbers(x) for k, x in v.items()}
    if isinstance(v, list):
        return [normalize_numbers(x) for x in v]
    return v


def extension_metadata(message: Message) -> object:
    md = json_format.MessageToDict(message.metadata) if message.HasField("metadata") else {}
    return md.get(EXTENSION_URI)


def request_part(message: Message) -> dict | None:
    """The single data Part {"skill", "transaction"} of an AAE-gated request."""
    data_parts = [p for p in message.parts if p.WhichOneof("content") == "data"]
    if len(data_parts) != 1:
        return None
    data = normalize_numbers(json_format.MessageToDict(data_parts[0].data))
    if not isinstance(data, dict) or set(data) != {"skill", "transaction"}:
        return None
    if not isinstance(data["skill"], str) or not isinstance(data["transaction"], dict):
        return None
    return data


def _invalid(reason_code: str, message: str) -> InvalidParamsError:
    # error.data becomes google.rpc.ErrorInfo.metadata, whose values are strings.
    return InvalidParamsError(message=message,
                              data={"extension": EXTENSION_URI, "reason_code": reason_code})


# --- configuration -----------------------------------------------------------------

@dataclass
class ProfileConfig:
    audience: str
    skills: dict[str, dict]
    accepted_issuers: list[str] | None
    did_methods: list[str]
    required: bool = True
    own_aae: str | None = None

    def params(self) -> dict:
        p = {
            "draft": AAE_DRAFT,
            "audience": self.audience,
            "skills": self.skills,
            "did_methods": self.did_methods,
            "max_ancestors": MAX_ANCESTORS,
        }
        if self.accepted_issuers is not None:
            p["accepted_issuers"] = self.accepted_issuers
        if self.own_aae:
            p["own_aae"] = {"jws": self.own_aae}
        return p


def build_agent_card(base_url: str, cfg: ProfileConfig) -> AgentCard:
    ext = AgentExtension(
        uri=EXTENSION_URI,
        description=("Requests to gated skills must carry an AAE (Agent Authorization Envelope, "
                     f"{AAE_DRAFT}) issued to the calling agent; it is verified per section 5 "
                     "before the task proceeds."),
        required=cfg.required,
    )
    ext.params.update(cfg.params())
    return AgentCard(
        name="Example Supplier Agent",
        description="Accepts quotes and purchase orders from buyer agents that present an AAE.",
        version="1.0.0",
        provider=AgentProvider(organization="Example Supplier Co", url="https://supplier.example"),
        capabilities=AgentCapabilities(streaming=False, push_notifications=False, extensions=[ext]),
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json", "text/plain"],
        skills=[
            AgentSkill(id="get-quote", name="Get quote", tags=["procurement"],
                       description="Price a list of items. AAE action: read."),
            AgentSkill(id="place-order", name="Place order", tags=["procurement"],
                       description="Place a purchase order. AAE action: pay."),
        ],
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", protocol_version="1.0",
                                             url=base_url.rstrip("/") + RPC_PATH)],
    )


# --- request handler: protocol-level checks ---------------------------------------

class AaeRequestHandler(DefaultRequestHandler):
    """Adds the profile's protocol checks in front of the SDK handler (spec 8.1)."""

    def __init__(self, *args, required: bool, **kwargs):
        super().__init__(*args, **kwargs)
        self._required = required

    async def on_message_send(self, params: SendMessageRequest, context: ServerCallContext):
        activated = EXTENSION_URI in context.requested_extensions
        if not activated:
            if self._required:
                raise ExtensionSupportRequiredError(
                    message=f"Extension {EXTENSION_URI} is required and was not activated",
                    data={"extension": EXTENSION_URI})
            return await super().on_message_send(params, context)
        md = extension_metadata(params.message)
        if params.message.task_id:
            if not isinstance(md, dict) or not isinstance(md.get("challenge_response"), str):
                raise _invalid("challenge_response_missing",
                               f"metadata[{EXTENSION_URI}].challenge_response is required")
        else:
            if not isinstance(md, dict) or not isinstance(md.get("aae"), str):
                raise _invalid("aae_missing", f"metadata[{EXTENSION_URI}].aae is required")
            # Shape only. The count bound is applied in step 9 and reported as a
            # rejection, not a transport error (AAE -02 sections 5 step 9, 7.9).
            anc = md.get("ancestor_jws", [])
            if not isinstance(anc, list) or not all(isinstance(a, str) for a in anc):
                raise _invalid("ancestor_jws_invalid", "ancestor_jws must be an array of strings")
            if request_part(params.message) is None:
                raise _invalid("request_part_invalid",
                               'exactly one data Part {"skill", "transaction"} is required')
        return await super().on_message_send(params, context)


# --- executor: AAE verification and the skill itself -------------------------------

class SkillFailed(Exception):
    """The skill ran and did not succeed. The authorization decision stands."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# What the example supplier stocks. An order for anything else is accepted by
# the AAE check and then fails in the skill: the paired case of section 8.3.
CATALOGUE = frozenset({"PAPER-A4", "TONER-K1"})


def perform_skill(skill: str, tx: dict) -> dict:
    if skill == "place-order":
        unknown = sorted({i.get("sku") for i in tx.get("items", []) if isinstance(i, dict)}
                         - CATALOGUE, key=str)
        if unknown:
            raise SkillFailed(f"not in catalogue: {', '.join(map(str, unknown))}")
        return {"order_id": "PO-0001", "status": "confirmed",
                "amount": tx.get("amount"), "currency": tx.get("currency"),
                "items": tx.get("items", [])}
    return {"quote": {"items": tx.get("items", []), "valid_minutes": 30}}


@dataclass
class _Pending:
    aae: str
    ancestor_jws: list
    skill: str
    transaction: dict
    aae_id: str
    nonce: str
    request_digest: str


@dataclass
class SupplierExecutor(AgentExecutor):
    cfg: ProfileConfig
    verifier: AaeVerifier
    binding: SubjectBinding
    clock: callable = utc_now
    perform: callable = perform_skill
    pending: dict[str, _Pending] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def rp_domain(self) -> str:
        return urlsplit(self.cfg.audience).hostname or ""

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        with self.lock:
            self.pending.pop(context.task_id or "", None)
        await TaskUpdater(event_queue, context.task_id or "", context.context_id or "").cancel()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id, context_id, msg = context.task_id, context.context_id, context.message
        updater = TaskUpdater(event_queue, task_id, context_id)
        if context.current_task is None:
            await event_queue.enqueue_event(Task(
                id=task_id, context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED), history=[msg]))
            await self._first_message(context, updater)
        else:
            with self.lock:
                pending = self.pending.pop(task_id, None)
            if pending is None or context.current_task.status.state != TaskState.TASK_STATE_AUTH_REQUIRED:
                await self._reject(updater, Reject(0, "no_pending_challenge",
                                                   "this task has no outstanding AAE challenge"))
                return
            await self._challenge_response(context, updater, pending)

    async def _first_message(self, context: RequestContext, updater: TaskUpdater) -> None:
        msg = context.message
        if EXTENSION_URI not in context.requested_extensions:
            req = request_part(msg)
            await self._reject(updater, Reject(0, "extension_not_activated"),
                               request_digest(req) if req is not None else None)
            return
        md = extension_metadata(msg)
        req = request_part(msg)
        # Frozen here: the challenge response cannot change the request (6.3),
        # so this digest is the one every result on this task reports.
        digest = request_digest(req)
        skill = self.cfg.skills.get(req["skill"])
        if skill is None:
            await self._reject(updater, Reject(0, "skill_not_gated", req["skill"]), digest)
            return
        now = self.clock()
        try:
            vc = self.verifier.precheck(md["aae"], now)
        except Reject as r:
            await self._reject(updater, r, digest)
            return
        nonce = self.binding.mint(self.cfg.audience, vc["id"], now)
        with self.lock:
            self.pending[context.task_id] = _Pending(
                aae=md["aae"], ancestor_jws=md.get("ancestor_jws", []), skill=req["skill"],
                transaction=req["transaction"], aae_id=vc["id"], nonce=nonce,
                request_digest=digest)
        challenge = {"nonce": nonce, "aud": self.cfg.audience, "aae_id": vc["id"]}
        status_msg = updater.new_agent_message(parts=[Part(
            text="AAE steps 1-3 passed. Prove control of credentialSubject.id: return a JWS "
                 "over {nonce, aud, iat, aae_id} signed with an authentication key of that DID.")])
        status_msg.metadata.update({EXTENSION_URI: {"challenge": challenge}})
        status_msg.extensions.append(EXTENSION_URI)
        await updater.requires_auth(message=status_msg)

    async def _challenge_response(self, context: RequestContext, updater: TaskUpdater,
                                  p: _Pending) -> None:
        md = extension_metadata(context.message)
        response = md.get("challenge_response") if isinstance(md, dict) else None
        if EXTENSION_URI not in context.requested_extensions or not isinstance(response, str):
            await self._reject(updater, Reject(4, "challenge_response_missing"),
                               p.request_digest)
            return
        now = self.clock()
        action = self.cfg.skills[p.skill]["action"]
        tx = p.transaction

        def subject_binding(vc: dict) -> None:
            try:
                self.binding.verify_response(
                    response, subject_did=vc["credentialSubject"]["id"], aae_id=vc["id"],
                    aud=self.cfg.audience, expected_nonce=p.nonce, now=now)
            except ChallengeError as exc:
                raise Reject(4, exc.reason.split(":")[0], exc.reason) from exc

        try:
            accepted = self.verifier.verify(
                p.aae, now=now, action=action, subject_binding=subject_binding,
                ancestor_jws=p.ancestor_jws, transaction=tx,
                action_ctx={"amount": tx.get("amount"), "currency": tx.get("currency"),
                            "domain": self.rp_domain})
        except Reject as r:
            await self._reject(updater, r, p.request_digest)
            return

        receipt = {
            "verdict": "ACCEPT",
            "draft": AAE_DRAFT,
            "steps_passed": accepted.steps,
            "aae_id": accepted.vc["id"],
            "issuer": accepted.root_vc["issuer"],
            "subject": accepted.vc["credentialSubject"]["id"],
            "skill": p.skill,
            "action": action,
            "verified_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request_digest": p.request_digest,
        }
        if accepted.enforce_result is not None:
            receipt["enforce"] = {"verdict": accepted.enforce_result["verdict"],
                                  "core": accepted.enforce_result["core"],
                                  "core_digest": accepted.enforce_result["core_digest"]}
        # The receipt records the decision and is in place before the skill runs.
        # What the skill then does is the task's terminal state, not the receipt.
        await updater.update_status(TaskState.TASK_STATE_WORKING,
                                    metadata={EXTENSION_URI: {"result": receipt}})
        try:
            output = self.perform(p.skill, tx)
        except SkillFailed as exc:
            await updater.failed(message=updater.new_agent_message(parts=[Part(
                text=f"{p.skill} failed: {exc.reason}. AAE {accepted.vc['id']} was verified; "
                     "the failure is the skill's, not the authorization's.")]))
            return
        await updater.add_artifact(parts=[Part(data=_to_value(output))],
                                   name="result", last_chunk=True)
        await updater.complete(message=updater.new_agent_message(
            parts=[Part(text=f"{p.skill} done; AAE {accepted.vc['id']} verified.")]))

    @staticmethod
    async def _reject(updater: TaskUpdater, r: Reject, digest: str | None = None) -> None:
        result = {
            "verdict": "REJECT",
            "draft": AAE_DRAFT,
            "step": r.step,
            "step_name": STEP_NAMES.get(r.step, "unknown"),
            "reason_code": r.reason,
        }
        if digest is not None:
            result["request_digest"] = digest
        if r.detail:
            result["detail"] = r.detail
        if r.enforce_result is not None:
            result["enforce"] = {"verdict": r.enforce_result["verdict"],
                                 "core": r.enforce_result["core"],
                                 "core_digest": r.enforce_result["core_digest"]}
        text = f"AAE rejected at step {r.step} ({result['step_name']}): {r.reason}"
        msg = updater.new_agent_message(parts=[Part(text=text)])
        msg.metadata.update({EXTENSION_URI: {"result": result}})
        msg.extensions.append(EXTENSION_URI)
        await updater.update_status(TaskState.TASK_STATE_REJECTED, message=msg,
                                    metadata={EXTENSION_URI: {"result": result}})


def _to_value(obj):
    from google.protobuf.struct_pb2 import Value
    v = Value()
    json_format.ParseDict(obj, v)
    return v


# --- ASGI app ----------------------------------------------------------------------

class ActivatedExtensionsHeader:
    """Echo the activated extensions in the A2A-Extensions response header
    (A2A extensions topic, "Extension Activation", step 3). The SDK version used
    here does not set it."""

    def __init__(self, app, supported: set[str]):
        self.app, self.supported = app, supported

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        requested: set[str] = set()
        for k, v in scope.get("headers", []):
            if k.decode("latin-1").lower() == A2A_EXTENSIONS_HEADER.lower():
                requested |= {u.strip() for u in v.decode("latin-1").split(",") if u.strip()}
        activated = sorted(requested & self.supported)

        async def send_wrapper(message):
            if message["type"] == "http.response.start" and activated:
                headers = list(message.get("headers", []))
                headers.append((A2A_EXTENSIONS_HEADER.encode(), ",".join(activated).encode()))
                message = {**message, "headers": headers}
            await send(message)

        return await self.app(scope, receive, send_wrapper)


def create_supplier_app(base_url: str, *, resolver: LocalDidResolver,
                        accepted_issuers: list[str] | None, own_aae: str | None = None,
                        clock=utc_now, verifier: AaeVerifier | None = None,
                        required: bool = True) -> tuple[Starlette, AgentCard, SupplierExecutor]:
    cfg = ProfileConfig(
        audience=base_url.rstrip("/") + RPC_PATH,
        skills={"get-quote": {"action": "read"}, "place-order": {"action": "pay"}},
        accepted_issuers=accepted_issuers,
        did_methods=["example"],
        required=required,
        own_aae=own_aae,
    )
    card = build_agent_card(base_url, cfg)
    assert find_extension_by_uri(card, EXTENSION_URI) is not None
    executor = SupplierExecutor(
        cfg=cfg,
        verifier=verifier or AaeVerifier(resolver, accepted_issuers=accepted_issuers),
        binding=SubjectBinding(resolver),
        clock=clock,
    )
    handler = AaeRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore(),
                                agent_card=card, required=cfg.required)
    routes = create_agent_card_routes(agent_card=card) + create_jsonrpc_routes(
        request_handler=handler, rpc_url=RPC_PATH)
    app = Starlette(routes=routes)
    app.add_middleware(ActivatedExtensionsHeader, supported={EXTENSION_URI})
    return app, card, executor
