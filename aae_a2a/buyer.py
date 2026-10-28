"""Buyer agent: an A2A client that holds an AAE issued to its DID and presents
it to the supplier under the AAE extension profile (spec sections 6-7).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import httpx
from google.protobuf import json_format
from google.protobuf.struct_pb2 import Value

from a2a.client import A2ACardResolver, ClientCallContext, ClientConfig, create_client
from a2a.extensions.common import find_extension_by_uri
from a2a.types import AgentCard, Message, Part, Role, SendMessageRequest, Task, TaskState

from .challenge import utc_now
from .constants import A2A_EXTENSIONS_HEADER, AAE_DRAFT, EXTENSION_URI
from .jose import b64url_decode, sign_compact, strict_json
from .testkeys import demo_key, kid_of


class ProfileError(Exception):
    """The supplier's card or challenge does not match what this client accepts."""


@dataclass
class BuyerAgent:
    base_url: str
    name: str = "buyer"
    httpx_client: httpx.AsyncClient | None = None
    clock: callable = utc_now
    card: AgentCard | None = None
    params: dict = field(default_factory=dict)
    _a2a: object = None

    async def discover(self) -> AgentCard:
        client = self.httpx_client or httpx.AsyncClient()
        try:
            self.card = await A2ACardResolver(client, self.base_url).get_agent_card()
        finally:
            if self.httpx_client is None:
                await client.aclose()
        ext = find_extension_by_uri(self.card, EXTENSION_URI)
        if ext is None:
            raise ProfileError("supplier does not declare the AAE extension")
        self.params = json_format.MessageToDict(ext.params)
        if self.params.get("draft") != AAE_DRAFT:
            raise ProfileError(f"unsupported AAE draft {self.params.get('draft')!r}")
        return self.card

    async def _client(self):
        if self._a2a is None:
            cfg = ClientConfig(streaming=False, httpx_client=self.httpx_client)
            self._a2a = await create_client(self.card, client_config=cfg)
        return self._a2a

    async def aclose(self) -> None:
        if self._a2a is not None:
            await self._a2a.close()
            self._a2a = None

    @staticmethod
    def _ctx(activate: bool) -> ClientCallContext:
        return ClientCallContext(
            service_parameters={A2A_EXTENSIONS_HEADER: EXTENSION_URI} if activate else {})

    async def _send(self, message: Message, activate: bool) -> Task:
        client = await self._client()
        async for event in client.send_message(SendMessageRequest(message=message),
                                               context=self._ctx(activate)):
            if event.HasField("task"):
                return event.task
        raise ProfileError("supplier answered without a task")

    def request_message(self, skill: str, transaction: dict, *, aae: str | None,
                        ancestor_jws: list[str] | None = None) -> Message:
        data = Value()
        json_format.ParseDict({"skill": skill, "transaction": transaction}, data)
        msg = Message(role=Role.ROLE_USER, message_id=str(uuid.uuid4()),
                      parts=[Part(data=data, media_type="application/json"),
                             Part(text=f"Request: {skill}")])
        if aae is not None:
            body = {"aae": aae}
            if ancestor_jws:
                body["ancestor_jws"] = ancestor_jws
            msg.metadata.update({EXTENSION_URI: body})
            msg.extensions.append(EXTENSION_URI)
        return msg

    def answer_challenge(self, challenge: dict, expected_aae_id: str) -> str:
        """Sign {nonce, aud, iat, aae_id} with this agent's authentication key.

        Before signing, the client checks that the challenge names the audience
        declared in the card it discovered and the envelope it presented, so it
        cannot be used to sign for another relying party (spec section 7.3)."""
        if set(challenge) != {"nonce", "aud", "aae_id"}:
            raise ProfileError("challenge members")
        if challenge["aud"] != self.params.get("audience"):
            raise ProfileError("challenge audience differs from the Agent Card")
        if challenge["aae_id"] != expected_aae_id:
            raise ProfileError("challenge names another envelope")
        iat = self.clock().strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"nonce": challenge["nonce"], "aud": challenge["aud"], "iat": iat,
                   "aae_id": challenge["aae_id"]}
        return sign_compact({"alg": "EdDSA", "kid": kid_of(self.name)}, payload, demo_key(self.name))

    async def request(self, skill: str, transaction: dict, *, aae: str | None,
                      aae_id: str | None = None, ancestor_jws: list[str] | None = None,
                      activate: bool = True, respond=None) -> Task:
        """Full flow. Returns the final Task (COMPLETED or FAILED after an accepted
        presentation, REJECTED otherwise), or raises the
        SDK's A2A error for a JSON-RPC error. `respond` may replace the
        challenge-response producer (tests use it to send bad responses)."""
        task = await self._send(self.request_message(skill, transaction, aae=aae,
                                                     ancestor_jws=ancestor_jws), activate)
        if task.status.state != TaskState.TASK_STATE_AUTH_REQUIRED:
            return task
        md = json_format.MessageToDict(task.status.message.metadata)
        challenge = md[EXTENSION_URI]["challenge"]
        expected = aae_id or (_aae_id_of(aae) if aae else None)
        response = (respond or self.answer_challenge)(challenge, expected)
        follow_up = Message(role=Role.ROLE_USER, message_id=str(uuid.uuid4()),
                            task_id=task.id, context_id=task.context_id,
                            parts=[Part(text="AAE challenge response")])
        follow_up.metadata.update({EXTENSION_URI: {"challenge_response": response}})
        follow_up.extensions.append(EXTENSION_URI)
        return await self._send(follow_up, activate)


def task_result(task: Task) -> dict | None:
    md = json_format.MessageToDict(task.metadata) if task.HasField("metadata") else {}
    return (md.get(EXTENSION_URI) or {}).get("result")


def _aae_id_of(aae: str) -> str | None:
    """Read the id of the client's own AAE (no verification needed for that)."""
    try:
        return strict_json(b64url_decode(aae.split(".")[1])).get("id")
    except Exception:
        return None
