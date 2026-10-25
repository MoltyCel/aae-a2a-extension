# AAE Extension for A2A

An [A2A](https://github.com/a2aproject/A2A) extension that carries an AAE
(Agent Authorization Envelope) in A2A messages and has the receiving agent
verify it before a skill runs.

- Extension URI: `https://moltrust.ch/extensions/aae/v1`
- Specification: [spec/aae-a2a-extension-v1.md](spec/aae-a2a-extension-v1.md)
- Status: **draft v1**. Not an official or experimental A2A extension.
- Built against A2A v1.0.1 and
  [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/).

An AAE is a W3C Verifiable Credential secured as an EdDSA compact JWS
(`cty: aae+json`) with three blocks: MANDATE (what the agent may do),
CONSTRAINTS (limits) and VALIDITY (time bounds). The profile defines where the
AAE goes in an A2A message, how the server proves the caller controls the
AAE's subject DID (a nonce challenge over `TASK_STATE_AUTH_REQUIRED`), how the
requested skill maps to a mandate action, and how acceptance or rejection is
reported (the failing verification step and a reason code).

## Run the demo

Requires Python 3.12.

```
make demo
```

This creates `.venv` from the hash-pinned `requirements.txt`, starts a
supplier agent on `127.0.0.1`, and runs a buyer agent against it over A2A
JSON-RPC:

- (a) an order inside the mandate: accepted, task completed, receipt in the
  task metadata;
- (b) an order above the `max_transaction_value` constraint: task rejected at
  step 7;
- (c) the extension not activated, the AAE missing, and a forged AAE:
  `ExtensionSupportRequiredError`, `InvalidParamsError`, and a task rejected at
  step 1.

Without `make`: `python -m pip install --require-hashes --no-deps -r requirements.txt`,
then `python -m aae_a2a.demo`.

## Tests

```
make test       # unit and end-to-end tests
make vectors    # also run the verifier against MoltyCel/aae-conformance-vectors
```

## Layout

| Path | Content |
| :-- | :-- |
| `spec/` | The extension specification. |
| `aae_a2a/verifier.py` | AAE -02 Section 5 verification algorithm. |
| `aae_a2a/enforce.py` | AAE -02 grant evaluation (Sections 2.2.1-2.2.3, 2.5). |
| `aae_a2a/challenge.py` | Subject binding challenge and response (Section 5, step 4). |
| `aae_a2a/server.py` | Supplier agent: Agent Card, request handler, executor. |
| `aae_a2a/buyer.py` | Buyer agent: discovery, presentation, challenge response. |
| `aae_a2a/testkeys.py` | Deterministic test keys and `did:example` documents. |
| `upstream/` | Draft text for a proposal issue in `a2aproject/A2A`. |

## Keys

All keys in this repository are derived from public labels and exist only to
make the demo reproducible. They are not secrets. Do not use them for anything
else.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); parts of the
verifier are derived from
[MoltyCel/aae-conformance-vectors](https://github.com/MoltyCel/aae-conformance-vectors).
