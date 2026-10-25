"""End-to-end demo: a buyer agent and a supplier agent over A2A JSON-RPC on
localhost. Run with `python -m aae_a2a.demo` (or `make demo`).
"""
from __future__ import annotations

import asyncio
import json
import socket
import threading
import time

import uvicorn
from google.protobuf import json_format

from a2a.types import TaskState
from a2a.utils.errors import A2AError, JSON_RPC_ERROR_CODE_MAP

from .buyer import BuyerAgent, task_result
from .challenge import utc_now
from .constants import EXTENSION_URI
from .jose import sign_compact
from .server import normalize_numbers, create_supplier_app
from .testkeys import (buyer_constraints, buyer_mandate, demo_key, demo_resolver, did_of,
                       issue_buyer_aae, issue_supplier_aae, kid_of, make_vc)
from .verifier import AaeVerifier, Reject


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(app, port: int) -> uvicorn.Server:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("supplier did not start")
        time.sleep(0.05)
    return server


def _show_task(task) -> None:
    print(f"   task state : {TaskState.Name(task.status.state)}")
    res = task_result(task)
    if res and res.get("verdict") == "REJECT":
        print(f"   rejected   : step {int(res['step'])} ({res['step_name']}), "
              f"reason_code={res['reason_code']}" + (f" - {res['detail']}" if res.get("detail") else ""))
    elif res:
        steps = ",".join(str(int(s)) for s in res["steps_passed"])
        print(f"   receipt    : verdict={res['verdict']} steps={steps} aae_id={res['aae_id']}")
        for art in task.artifacts:
            data = normalize_numbers(json_format.MessageToDict(art.parts[0].data))
            print(f"   artifact   : {json.dumps(data, sort_keys=True)}")


def _show_error(exc: A2AError) -> None:
    code = JSON_RPC_ERROR_CODE_MAP.get(type(exc))
    print(f"   JSON-RPC error {code} {type(exc).__name__}: {exc.message}")
    if exc.data:
        print(f"   ErrorInfo.metadata: {json.dumps(exc.data, sort_keys=True)}")


async def run(base_url: str) -> int:
    buyer = BuyerAgent(base_url)
    card = await buyer.discover()
    print(f"Supplier card: {card.name}; extension {EXTENSION_URI} "
          f"required={card.capabilities.extensions[0].required}")
    print(f"   params: draft={buyer.params['draft']} audience={buyer.params['audience']}")
    print(f"           skills={json.dumps(buyer.params['skills'], sort_keys=True)} "
          f"accepted_issuers={buyer.params['accepted_issuers']}")
    try:
        own = AaeVerifier(demo_resolver()).precheck(buyer.params["own_aae"]["jws"], utc_now())
        print(f"   supplier's own AAE (steps 1-3 checked by buyer): subject={own['credentialSubject']['id']}"
              f" actions={own['credentialSubject']['aae']['mandate']['actions']}")
    except Reject as r:
        print(f"   supplier's own AAE rejected at step {r.step}: {r.reason}")

    now = utc_now()
    domains = ["127.0.0.1", "supplier.example"]
    aae = issue_buyer_aae(now, domains)
    outcomes = []

    print("\n(a) place-order 120 EUR, inside the mandate (cap 500 EUR)")
    task = await buyer.request("place-order", {"amount": 120, "currency": "EUR",
                                               "items": [{"sku": "PAPER-A4", "qty": 20}]}, aae=aae)
    _show_task(task)
    outcomes.append(task.status.state == TaskState.TASK_STATE_COMPLETED)

    print("\n(b) place-order 900 EUR, over the max_transaction_value constraint")
    task = await buyer.request("place-order", {"amount": 900, "currency": "EUR",
                                               "items": [{"sku": "CHAIR-01", "qty": 6}]}, aae=aae)
    _show_task(task)
    res = task_result(task) or {}
    outcomes.append(task.status.state == TaskState.TASK_STATE_REJECTED and int(res.get("step", -1)) == 7)

    print("\n(c1) extension not activated (no A2A-Extensions header), card says required")
    try:
        await buyer.request("place-order", {"amount": 120, "currency": "EUR"}, aae=aae, activate=False)
        outcomes.append(False)
    except A2AError as exc:
        _show_error(exc)
        outcomes.append(JSON_RPC_ERROR_CODE_MAP.get(type(exc)) == -32008)

    print("\n(c2) extension activated, AAE missing")
    try:
        await buyer.request("place-order", {"amount": 120, "currency": "EUR"}, aae=None)
        outcomes.append(False)
    except A2AError as exc:
        _show_error(exc)
        outcomes.append((exc.data or {}).get("reason_code") == "aae_missing")

    print("\n(c3) forged AAE: claims the issuer's kid, signed with another key")
    forged_vc = make_vc(subject=did_of("buyer"), issuer=did_of("issuer"), mandate=buyer_mandate(),
                        constraints=buyer_constraints(domains), not_before=now, not_after=now)
    forged_vc["credentialSubject"]["aae"]["constraints"]["max_transaction_value"]["value"] = 1_000_000
    forged = sign_compact({"alg": "EdDSA", "cty": "aae+json", "kid": kid_of("issuer")},
                          forged_vc, demo_key("mallory"))
    task = await buyer.request("place-order", {"amount": 900, "currency": "EUR"}, aae=forged)
    _show_task(task)
    res = task_result(task) or {}
    outcomes.append(task.status.state == TaskState.TASK_STATE_REJECTED and int(res.get("step", -1)) == 1)

    await buyer.aclose()
    ok = all(outcomes)
    print(f"\n{sum(outcomes)}/{len(outcomes)} scenarios behaved as specified")
    return 0 if ok else 1


def main() -> int:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    app, _card, _ = create_supplier_app(
        base_url, resolver=demo_resolver(), accepted_issuers=[did_of("issuer")],
        own_aae=issue_supplier_aae(utc_now()))
    server = _start_server(app, port)
    print(f"Supplier agent listening on {base_url} (card at /.well-known/agent-card.json)\n")
    try:
        return asyncio.run(run(base_url))
    finally:
        server.should_exit = True


if __name__ == "__main__":
    raise SystemExit(main())
