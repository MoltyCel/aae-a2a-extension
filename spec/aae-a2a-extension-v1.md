# AAE Extension for A2A, Version 1

| | |
| :-- | :-- |
| Extension URI | `https://moltrust.ch/extensions/aae/v1` |
| Status | Draft v1 |
| A2A baseline | A2A Protocol v1.0.1 (tag `v1.0.1`, commit `3303592588e388e62e0f69f701af531d2f4e3991`) |
| AAE baseline | [draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/) ("AAE -02") |
| Editor | Lars Kroehl, CryptoKRI GmbH (MolTrust) |
| License | Apache License 2.0 |

## Abstract

This document specifies an A2A extension that carries an AAE (Agent
Authorization Envelope) in A2A messages, lets an A2A server agent verify it
with the AAE -02 Section 5 verification algorithm before it performs a skill,
and reports the outcome through A2A task states and errors. It also lets an
agent publish its own AAE in its Agent Card.

In A2A terms this is a profile extension: it constrains the shape of request
messages for the skills it gates and uses `metadata` for its own data. It
defines no new RPC methods, task states or core fields.

## 1. Conventions and References

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14
([RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119),
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174)) when, and only when,
they appear in all capitals, as shown here.

Normative references:

- **A2A**: A2A Protocol Specification v1.0.1, `docs/specification.md` and
  `specification/a2a.proto` in [a2aproject/A2A](https://github.com/a2aproject/A2A)
  at tag `v1.0.1` (commit `3303592588e388e62e0f69f701af531d2f4e3991`).
  Section numbers below refer to that file. The extension topic pages
  `docs/topics/extensions.md` and `docs/topics/extension-and-binding-governance.md`
  were read at `main` commit `98279d62316361ba8451eaef300f72b72e169185`
  (2026-10-20); A2A Section 7.6.4 ("In-Task Authorization Scope") exists on
  that commit and not yet in the v1.0.1 tag, and this profile is written to
  satisfy it.
- **AAE -02**: L. K. Kroehl, "Agent Authorization Envelope (AAE): A
  Machine-Evaluable Authorization Structure for Autonomous AI Agents",
  draft-kroehl-agentic-trust-aae-02, 6 September 2026. "-02 §N" refers to its
  sections. This profile is built against -02 only.
- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) (JWS),
  [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037) (EdDSA for JOSE),
  [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339).

Terms: *client* and *server* are the A2A client and A2A server (remote agent).
The server is the AAE *relying party* (-02 §1.2); the client is the agent that
presents the AAE. *Gated skill* is a skill whose invocation this extension
governs. JSON member names of A2A objects follow the ProtoJSON camelCase of
A2A §5.5; members of objects this extension defines use snake_case, matching
the member names of AAE -02.

## 2. Extension URI and Versioning

The identifier of this extension is:

```
https://moltrust.ch/extensions/aae/v1
```

It is the only URI for this version. It is an identifier: clients and servers
compare it as an exact string, and HTTP access to it is not required for
interoperability (the A2A governance page states the same for URIs under the
official prefix). The specification SHOULD also be published at that URI.

Version 1 is bound to AAE -02. A change that alters data structures, required
parameters or processing in a way an existing implementation would not accept
requires a new URI (A2A §4.6.3). A profile for a later AAE revision will use a
new URI; a server MUST NOT accept a `params.draft` value it does not
implement, and MUST NOT fall back to another version (A2A §4.6.3).

This extension depends on no other extension.

## 3. Overview

```
 Client (holds AAE for its DID)                 Server (relying party)
 ------------------------------                 ----------------------
 GET /.well-known/agent-card.json  ---------->  capabilities.extensions[]: uri, required, params
 SendMessage                       ---------->  protocol checks (Section 7.1)
   A2A-Extensions: <URI>                        -02 §5 steps 1-3 (Section 7.2)
   message.metadata[URI] = {aae, ancestor_jws?}
   message.parts = [data {skill, transaction}, ...]
                                   <----------  Task TASK_STATE_AUTH_REQUIRED
                                                status.message.metadata[URI] = {challenge}
 SendMessage (same taskId)         ---------->  -02 §5 steps 1-9 (Section 7.4)
   message.metadata[URI] = {challenge_response}
                                                accepted: the skill runs
                                   <----------  Task TASK_STATE_COMPLETED or TASK_STATE_FAILED (the skill's outcome),
                                                  metadata[URI].result = ACCEPT receipt {..., request_digest}
                                           or   rejected: the skill is never invoked
                                                Task TASK_STATE_REJECTED,
                                                  metadata[URI].result = {step, reason_code, request_digest}
```

The result records the authorization decision; the task state reports what
happened. A rejection ends the task before the skill. An acceptance hands the
request to the skill, and the skill's outcome decides between
`TASK_STATE_COMPLETED` and `TASK_STATE_FAILED`; the ACCEPT receipt stands in
both (Section 8.3).

The two-message exchange exists because -02 §5 step 4 requires a relying-party
nonce. It uses the in-task authorization pattern of A2A §7.6
(`TASK_STATE_AUTH_REQUIRED`), with the credential exchanged in band as A2A
§7.6.1 permits when an extension defines it.

## 4. Agent Card Declaration

A server that supports this extension MUST list it in
`AgentCard.capabilities.extensions` as an `AgentExtension` (A2A §4.4.4) with:

- `uri`: the URI of Section 2.
- `description`: free text.
- `required`: `true` if every `SendMessage` to this agent MUST activate the
  extension; `false` if only requests to gated skills need it (Section 7.1).
- `params`: an object with the members below.

| Member | Type | Req. | Meaning |
| :-- | :-- | :-- | :-- |
| `draft` | string | REQUIRED | The AAE revision the server verifies against. For this version it MUST be `draft-kroehl-agentic-trust-aae-02`. |
| `audience` | string | REQUIRED | The audience identifier the server places in subject-binding challenges (-02 §5 step 4, `aud`). It SHOULD be the URL of the `AgentInterface` that receives the requests. |
| `skills` | object | REQUIRED | Maps each gated skill id (an `AgentSkill.id` in the same card) to an object `{"action": <string>}`, the AAE mandate action (-02 §2.2, §4) that invoking the skill requires. |
| `accepted_issuers` | array of strings | OPTIONAL | DIDs whose AAEs the server accepts as the root of authority (Section 7.5). If absent, issuer acceptance is local policy not disclosed in the card. |
| `did_methods` | array of strings | OPTIONAL | DID method names the server can resolve locally (for example `"web"`). -02 §5.2 defers DID methods that require outbound resolution; a client SHOULD NOT present an AAE whose issuer or subject uses a method not listed here. |
| `max_ancestors` | integer | OPTIONAL | The number of inline ancestors the server accepts in `ancestor_jws`. If present it MUST be at least 16 (-02 §5 step 9). |
| `own_aae` | object | OPTIONAL | The server's own AAE (Section 9): `{"jws": <compact JWS>}` or `{"uri": <https URL>}`. |
| `deferred_decisions` | boolean | OPTIONAL | `true` if the server holds a presentation whose grant verdict is PENDING until a ratification closes it (Section 7.6). Absent means `false`: PENDING is a rejection at step 6. |

Clients MUST ignore `params` members they do not understand. A gated skill
SHOULD also state its mapped action in its `AgentSkill.description`.

Example:

```json
{
  "capabilities": {
    "streaming": false,
    "extensions": [
      {
        "uri": "https://moltrust.ch/extensions/aae/v1",
        "description": "Requests to gated skills must carry an AAE issued to the calling agent.",
        "required": true,
        "params": {
          "draft": "draft-kroehl-agentic-trust-aae-02",
          "audience": "https://supplier.example/a2a/jsonrpc",
          "skills": {
            "get-quote":   {"action": "read"},
            "place-order": {"action": "pay"}
          },
          "accepted_issuers": ["did:web:registry.example"],
          "did_methods": ["web"],
          "max_ancestors": 16
        }
      }
    ]
  }
}
```

Because `params` steer what the client signs and presents, a client SHOULD
obtain the Agent Card over an authenticated channel and SHOULD verify the card
signature where the card is signed (A2A §8.4).

## 5. Activation

A client activates the extension per request with the `A2A-Extensions` service
parameter (A2A §3.2.6), carried as the HTTP header `A2A-Extensions` in the
JSON-RPC and HTTP+JSON bindings (A2A §9.2, §11.2) and as the `a2a-extensions`
metadata entry in the gRPC binding (A2A §10.2). The value is a comma-separated
list of extension URIs.

A client MUST activate the extension on every message that carries data this
extension defines, and MUST list the URI in `Message.extensions` of those
messages (A2A §4.6.2). The server SHOULD echo the URI in the `A2A-Extensions`
response header when it activated the extension.

## 6. Data Carried in Messages

All data this extension defines is placed in a `metadata` map under the key
equal to the extension URI (A2A §3.2.5, §4.6.2). The value is a JSON object.

### 6.1 Presentation Message

The message that invokes a gated skill without a `taskId` (a new task) is the
*presentation message*. It MUST carry:

`Message.metadata["https://moltrust.ch/extensions/aae/v1"]`:

| Member | Type | Req. | Meaning |
| :-- | :-- | :-- | :-- |
| `aae` | string | REQUIRED | The secured AAE: a JWS in compact serialization (-02 §2, §2.1). |
| `ancestor_jws` | array of strings | OPTIONAL | The ancestors of a delegated AAE, as compact JWS strings in any order (-02 §5 step 9, "Wire format for the chain"). This is the "embedded by the transport binding" case of -02 §3. |

and exactly one `Part` whose content is `data` (A2A §4.1.6), the *request
part*, whose value is an object with exactly these members:

| Member | Type | Meaning |
| :-- | :-- | :-- |
| `skill` | string | The id of the gated skill being invoked. |
| `transaction` | object | The parameters of the invocation. This object is the transaction that constraints are evaluated against (Section 7.4). |

The request part is the complete statement of what the client asks the server
to do. The message MAY carry `text` parts for humans; the server MUST NOT
derive any action, amount or other parameter of the invocation from parts
other than the request part.

Example:

```json
{
  "messageId": "6a1c...",
  "role": "ROLE_USER",
  "extensions": ["https://moltrust.ch/extensions/aae/v1"],
  "parts": [
    {"data": {"skill": "place-order",
              "transaction": {"amount": 120, "currency": "EUR",
                              "items": [{"sku": "PAPER-A4", "qty": 20}]}},
     "mediaType": "application/json"},
    {"text": "Request: place-order"}
  ],
  "metadata": {
    "https://moltrust.ch/extensions/aae/v1": {"aae": "eyJhbGciOiJFZERTQSIs..."}
  }
}
```

### 6.2 Challenge

When the presentation passes Section 7.2, the server returns a `Task` in
`TASK_STATE_AUTH_REQUIRED`. `Task.status.message.metadata[URI]` MUST be:

```json
{"challenge": {"nonce": "<nonce>", "aud": "<params.audience>", "aae_id": "<VC id>"}}
```

`aud` is the `params.audience` value; `aae_id` is the `id` of the presented
Verifiable Credential. `nonce` has the form of -02 §5 step 4, restated here
so that a server can be built from this profile alone:

```
nonce = <random> "." <expiry> "." <authenticator>

<random>         at least 32 lowercase hexadecimal digits (128 bits or more
                 of unpredictable data)
<expiry>         the absolute expiry in seconds since the Unix epoch, decimal,
                 equal to the minting time plus the nonce lifetime of
                 Section 7.4 step 4
<authenticator>  HMAC-SHA-256 (RFC 2104) over the ASCII string
                   <random> "." <expiry> "." <aud> "." <aae_id>
                 under a key held by the server alone and used for nothing
                 else, base64url without padding (43 characters)
```

The server that minted a nonce is the only party that can verify its
authenticator, and only it does so: a nonce answers a challenge on the task it
was issued for (Section 7.3) and is never presented to another server. A client
treats the nonce as opaque and returns it unchanged. What another party can
check from the form alone is whether a nonce is malformed; a server MUST reject
a challenge response whose nonce does not match the form (`nonce_malformed`)
before it verifies the authenticator. The status message SHOULD also carry a
`text` part that explains the request.

### 6.3 Challenge-Response Message

The client answers with a `SendMessage` whose `Message.taskId` and
`Message.contextId` are those of the task. It MUST carry
`Message.metadata[URI] = {"challenge_response": <compact JWS>}`, where the JWS
is the challenge response of -02 §5 step 4: payload exactly
`{"nonce", "aud", "iat", "aae_id"}`, `iat` an RFC 3339 timestamp, protected
header `alg` `"EdDSA"` and `kid` a DID URL whose DID equals
`credentialSubject.id`, signed with a key in that DID document's
`authentication` relationship. The JWS header MUST NOT carry `cty`
`aae+json`. The message MUST carry at least one part (A2A requires one); it
MUST NOT carry a request part, and the server MUST NOT use any part of it to
change the request.

Before signing, the client MUST check that `aud` equals `params.audience` from
the Agent Card it used and that `aae_id` equals the id of the AAE it
presented, and MUST NOT sign otherwise (Section 10.3).

### 6.4 Numbers

A2A carries `data` parts and `metadata` as `google.protobuf.Value` /
`google.protobuf.Struct`, which represent every number as an IEEE 754 double.
A server that receives the request part through such a layer cannot tell `120`
from `120.0`. For the purpose of -02 §2.5.1 (`range`, integers only) and §2.2.2
(`action_binding`, JCS over the action), a server MUST treat a number with an
integral value and absolute value at most 2^53 as an integer, and a client MUST
encode integer-valued fields (for example amounts in minor units) as JSON
integers within that range. JCS (RFC 8785) serializes both forms identically,
so digests are unaffected.

## 7. Server Processing

### 7.1 Protocol Checks

These checks are about whether the client followed this extension's
protocol. Their failures are A2A errors (A2A §3.3.2) and create no task.

1. If the card declares the extension `required: true` and the request does
   not activate it, the server MUST return `ExtensionSupportRequiredError`
   (A2A §3.3.4; JSON-RPC code `-32008`, A2A §5.4).
2. If the extension is `required: false`, is not activated, and the request
   targets a gated skill, the server MUST NOT perform the skill; it MUST
   reject the task with `reason_code` `extension_not_activated` (Section 8.2).
3. If the extension is activated on a presentation message and
   `metadata[URI].aae` is absent or not a string, `ancestor_jws` is present
   and not an array of strings, or there is not exactly one well-formed
   request part, the server MUST return `InvalidParamsError` (JSON-RPC
   `-32602`, A2A §9.5).
4. If the extension is activated on a message to an existing task with an
   outstanding challenge and `metadata[URI].challenge_response` is absent or
   not a string, the server MUST return `InvalidParamsError`.
5. If the extension is activated on a message to a task held under Section
   7.6 and `metadata[URI].ratification` is absent or not an object, the server
   MUST return `InvalidParamsError` (`ratification_malformed`).

For errors in 3 and 4 the server SHOULD include in the error details
(A2A §3.3.2, JSON-RPC `error.data`) a `google.rpc.ErrorInfo` whose `metadata`
contains `"extension": <URI>` and `"reason_code": <code from Section 8.4>`.

Size limits on inputs (-02 §7.9) are not protocol checks: an input over a
limit is a rejection reported per Section 8.2, not an A2A error.

### 7.2 Presentation: Steps 1-3

On a valid presentation message the server MUST:

1. Look up `params.skills[skill]`. If the skill is not gated, reject with
   `skill_not_gated` (step 0).
2. Run -02 §5 steps 1 (signature, signing authority), 2 (payload, schema,
   `cty` = `aae+json`) and 3 (temporal validity, including `validFrom`, -02
   §2.4) on `aae`.
3. For a non-delegated AAE, apply issuer acceptance (Section 7.5).

The signing-authority check of step 1 reads `issuer` and
`mandate.delegation` from the payload, which -02 parses in step 2. A server
MUST therefore read the `aae` in this order, here and when Section 7.4 runs
steps 1 and 2 again:

1. Bound the size (Section 10.6), split the compact JWS and parse the protected
   header (step 1).
2. Verify the signature over the signing input against the key the `kid`
   names: -02 §5 step 1 (a) to (d).
3. Parse the payload once, as UTF-8 JSON, rejecting duplicate member names at
   any depth. A payload that is not UTF-8, is not JSON or names a member twice
   is rejected at step 2 (`payload_not_json`); one that is JSON but not an
   object is rejected at step 2 (`payload_not_object`).
4. Check signing authority against the payload parsed in 3 (step 1).
5. Run the remaining checks of step 2, then step 3.

The payload parsed in 3 is the only reading of it. A server MUST NOT read it
for step 1 with a parser more lenient than the one of step 2: with duplicate
names allowed, a first-wins and a last-wins parser see different issuers in
the same token, and the step at which it fails would depend on the parser.

On failure the server MUST reject the task (Section 8.2) at the failing step.
On success it MUST mint a nonce per Section 6.2, bind it to this task, and
return the challenge of Section 6.2.

Steps 1-3 are run here so that a server does not issue challenges for
envelopes it would refuse anyway. They are run again in Section 7.4; the result
of this first run MUST NOT be reused, because time passes between the two
messages.

### 7.3 Nonce Binding

The server MUST bind each nonce to the task it was issued for and MUST accept
it only in a challenge response on that task. A task has at most one
outstanding challenge; after the server has processed a challenge response for
it, accepted or not, the challenge is spent. This binding is in addition to the
-02 §5 step 4 conditions, which bind the nonce to `aud` and `aae_id` but not to
a request.

### 7.4 Challenge Response: Steps 1-9

On a valid challenge-response message for a task with an outstanding challenge,
the server MUST run -02 §5 steps 1 to 9, in order, on the `aae` and
`ancestor_jws` of the presentation message, and stop at the first failing
step:

- **Step 1-3**: as in Section 7.2.
- **Step 4, subject binding**: verify `challenge_response` against all
  conditions (a)-(f) of -02 §5 step 4, its nonce format, the order of the
  nonce checks, the used-nonce store rules, the iat window, the JOSE profile
  (size bound before decoding, `alg` from an allowlist, no `b64: false`, no
  detached payload, no `crit`, duplicate member names rejected in header and
  payload, no `cty` `aae+json`) and the DID URL rules, plus Section 7.3.
  This exchange is the proof of possession of -02 §5 step 4; transport-level
  client authentication, if any, does not replace it.

  -02 leaves the nonce lifetime and the accepted clock skew to local policy.
  This profile fixes both, so that two servers decide the same challenge
  response the same way: the nonce lifetime is 300 seconds and the accepted
  skew is 60 seconds. With `now` the server's clock when it checks the
  response, the server MUST accept an `iat` from `now` minus 360 seconds to
  `now` plus 60 seconds, both bounds included, and MUST reject an `iat` later
  than that (`iat_in_future`) or earlier (`iat_too_old`). The expiry carried
  in the nonce is checked as well and independently (-02 §5 step 4).
- **Step 5, single use**: as in -02 §5 step 5 and §2.4. A presentation that is
  rejected in a later step SHOULD NOT consume the AAE.
- **Step 6, action**: the requested action is `params.skills[skill].action`.
  It MUST be in `mandate.actions`. If the mandate carries `grants`
  (-02 §2.2.1), the server MUST also evaluate them per -02 §2.2.3 with the
  request part's `transaction` as the transaction, whose `action` member is
  the action object A of -02 §2.2.2; `transaction.action.verb` MUST equal the
  requested action. DENY is a rejection at step 6 (`grant_deny`). PENDING is
  a rejection at step 6 (`grant_pending`) unless the server declares
  `deferred_decisions: true`, in which case it holds the presentation
  (Section 7.6). A server that does not implement -02 §2.2.3 MUST reject
  every AAE that carries `grants` (-02 §2.2.1).
- **Step 7, constraints** (-02 §2.3): the constraint types of -02 §2.3 map to
  the request as follows; everything else follows -02 §2.3 and §5 step 7
  (unrecognized required constraints reject, `required` absent means `true`).
  - `max_transaction_value`: `transaction.amount` (a JSON number) and
    `transaction.currency` (ISO 4217 code). A currency different from the
    constraint's is a rejection (`currency_mismatch`). If the constraint is
    required and `amount` is absent, it cannot be evaluated and the AAE is
    rejected.
  - `allowed_domains`: the host of `params.audience`, the domain the client is
    contacting. Host names compare case-insensitively.
  - `rate_limit`: the number of actions the server has accepted under this
    AAE `id` within `window`. A server that does not keep that state MUST
    reject an AAE with a required `rate_limit` (-02 §2.3).
- **Step 8, revocation**: per -02 §2.4 and §5 step 8. -02 §5.2 defers
  revocation lookup until a relying party has an egress path that constrains
  outbound requests; a server without one MUST reject an AAE carrying
  `revocation_check` (fail closed, `revocation_status_indeterminate`).
- **Step 9, delegation chain**: per -02 §3 and §5 step 9, with the ancestors
  taken only from `ancestor_jws`. The server MUST NOT dereference
  `delegator_aae_uri` (-02 §5.2). It MUST bound the supplied material before
  verifying it, MUST accept at least 16 ancestors, MUST index them by
  Verifiable Credential `id`, MUST reject duplicate ids, and MUST apply the
  narrowing rules including grant attenuation.

Then the server applies issuer acceptance (Section 7.5) to the root of the
chain. If all of this passes, the presentation is accepted: the server
transitions the task out of `TASK_STATE_AUTH_REQUIRED`, performs the skill
with exactly the request part of the presentation message, and reports per
Section 8.3. If any step fails, the server MUST NOT invoke the skill.

The authorization established this way covers that one request on that one
task. In the terms of A2A §7.6.4, it MUST NOT be taken to authorize any later
message on the task; a later request on the same task needs a new
presentation and challenge.

### 7.5 Issuer Acceptance

-02 §5 establishes that an AAE is authentic and well formed; it does not say
whose AAEs a relying party trusts. If `params.accepted_issuers` is present, the
server MUST reject (step 0, `issuer_not_accepted`) an AAE whose root issuer is
not in it. The root issuer is the `issuer` of the presented AAE if it is not
delegated, and otherwise the `issuer` of the root AAE reached in step 9.

### 7.6 Deferred Decisions

A grant with disposition `hold` yields PENDING (-02 §2.2.3 step 6). PENDING
states that the mandate defers the action to a decision that has not been made
(-02 §6.1). -02 closes such a verdict by appending a ratification record that
refers to it (-02 §6.3), signed by an authority the mandate itself names (-02
§6.4). This section fixes how the two records travel over A2A. It adds no
verdict, no record and no role: every record is one of -02, and the authorities
are the two mandate members of -02 §6.4.

**Holding.** When step 6 yields PENDING at a server that declares
`deferred_decisions: true`, the server runs steps 7 to 9 as it would for a
PERMIT. If one of them fails, it rejects at that step, since no decision could
make the request acceptable. Otherwise it MUST NOT invoke the skill and MUST
move the task to `TASK_STATE_INPUT_REQUIRED` (A2A §4.1.3), with this object as
`result` in `Task.status.message.metadata[URI]` and in `Task.metadata[URI]`:

| Member | Type | Meaning |
| :-- | :-- | :-- |
| `verdict` | string | `"PENDING"` |
| `draft` | string | The AAE revision verified against. |
| `steps_passed` | array of integers | The steps that passed; 6 is absent, it is the step held. |
| `enforce` | object | The verdict record of -02 §2.5.3: `{"verdict": "PENDING", "core", "core_digest"}`. |
| `authorities` | array of strings | The DIDs a ratification may come from, in this order: `mandate.principal.did`, then the `did` of each `mandate.ratification_authorities` entry that carries both a `did` and a `public_key` (-02 §6.4). |
| `aae_id` | string | The VC `id` of the presented AAE. |
| `request_digest` | string | Section 8.5. |
| `ratification` | object | Present after a ratification that did not close the hold (below). |

An authority decides by signing the statement of -02 §6.3 over
`enforce.core_digest`. How the record reaches an authority and how its proof
comes back is outside this profile. The single-use reservation of step 5 stays
in place while the task is held.

**Closing.** The decision arrives as a message on the held task, with the
extension activated, at least one part, no request part, and
`metadata[URI]`:

```json
{"ratification": {"decision": "APPROVED",
                  "authority_proof": {"mandate": {}, "authority": "<DID>",
                                      "signature": "<64 octets, hexadecimal>"}}}
```

`decision` is `APPROVED` or `DISAPPROVED`; `authority_proof` is the proof of
-02 §6.4. Any party may send the message: what counts is the proof, not the
sender. The server MUST compute the ratification record of -02 §6.3 over the
held verdict record. It takes the authority's key only from the mandate in the
proof, after binding that mandate to the record's `mandate_digest`, and it
does not interpret `role` (-02 §6.4). Then:

- Status RATIFIED, decision APPROVED: the action is authorized (-02 §6.3,
  Table 2). The server runs step 3 again at its current time and rejects at
  step 3 if the AAE has expired since the hold. Otherwise it performs the
  skill with exactly the held request part and reports per Section 8.3. The
  receipt's `steps_passed` contains 6, and the receipt carries `enforce`, the
  held PENDING record, and `ratification`.
- Status RATIFIED, decision DISAPPROVED: the hold ends in a refusal. The
  server rejects at step 6 with `ratification_disapproved`, carrying `enforce`
  and `ratification`, and releases the single-use reservation.
- Status REJECTED: the PENDING verdict stands (-02 §6.3). The task stays in
  `TASK_STATE_INPUT_REQUIRED` with the result above, `ratification` added. A
  later message on the task may carry another ratification.
- A caller error of -02 §6.4 (a decision that is neither value, among others)
  produces no record: the server returns `InvalidParamsError`
  (`ratification_malformed`) and the task is unchanged.

`ratification` is `{"status", "decision", "authority", "core", "core_digest"}`,
the record of -02 §6.3 with its digest; the trace in its core names a failed
predicate for a REJECTED status. In no case does the server edit or re-issue the
held record (-02 §6.3). A ratification authorizes the one transaction the held
record's `transaction_digest` names: the skill runs on the held request part,
and nothing in the ratification message can change it.

## 8. Result Reporting

### 8.1 Errors

| Condition | A2A error | JSON-RPC | `reason_code` |
| :-- | :-- | :-- | :-- |
| Required extension not activated | `ExtensionSupportRequiredError` | `-32008` | (none) |
| `aae` missing on presentation | `InvalidParamsError` | `-32602` | `aae_missing` |
| `ancestor_jws` not an array of strings | `InvalidParamsError` | `-32602` | `ancestor_jws_invalid` |
| No single well-formed request part | `InvalidParamsError` | `-32602` | `request_part_invalid` |
| `challenge_response` missing | `InvalidParamsError` | `-32602` | `challenge_response_missing` |

In the gRPC and HTTP+JSON bindings the same errors map per A2A §5.4, and
`reason_code` travels in the `google.rpc.ErrorInfo` metadata the same way.

### 8.2 Rejection

A failed AAE verification is an authorization decision, not a protocol error:
the server has decided not to perform the task. The server MUST move the task
to `TASK_STATE_REJECTED` (A2A §4.1.3) and MUST NOT perform the skill. It MUST
put the following object as `result` both in
`Task.status.message.metadata[URI]` and in `Task.metadata[URI]`:

| Member | Type | Meaning |
| :-- | :-- | :-- |
| `verdict` | string | `"REJECT"` |
| `draft` | string | The AAE revision verified against. |
| `step` | integer | The -02 §5 step that failed (1-9), or `0` for a check this profile defines (Sections 7.1 item 2, 7.2 item 1, 7.3, 7.5). |
| `step_name` | string | `profile`, `signature`, `payload_schema`, `temporal_validity`, `subject_binding`, `single_use`, `action`, `constraints`, `revocation`, `delegation_chain` for steps 0-9. |
| `reason_code` | string | Section 8.4. |
| `detail` | string | OPTIONAL. Diagnostic text; not normative. |
| `enforce` | object | Present when grant evaluation ran: `{"verdict", "core", "core_digest"}` per -02 §2.5.3. |
| `ratification` | object | Present when a held task was refused by a ratification (Section 7.6, `ratification_disapproved`): the -02 §6.3 record. |
| `request_digest` | string | REQUIRED when the task has a well-formed request part (Section 6.1), which is every rejection except `no_pending_challenge` and `extension_not_activated` without one. Computed per Section 8.5. |

The status message SHOULD also carry a `text` part stating step and reason.

The server reports the step at which the -02 §5 algorithm stopped. It SHOULD
NOT disclose more than `reason_code` and the step to a client whose subject
binding has not succeeded (Section 11).

Example, for the request part
`{"skill": "place-order", "transaction": {"amount": 900, "currency": "EUR"}}`
under an AAE capped at 500 EUR:

```json
{
  "status": {
    "state": "TASK_STATE_REJECTED",
    "message": {
      "role": "ROLE_AGENT",
      "parts": [{"text": "AAE rejected at step 7 (constraints): max_transaction_value_exceeded"}],
      "extensions": ["https://moltrust.ch/extensions/aae/v1"],
      "metadata": {"https://moltrust.ch/extensions/aae/v1": {"result": {
        "verdict": "REJECT", "draft": "draft-kroehl-agentic-trust-aae-02",
        "step": 7, "step_name": "constraints",
        "reason_code": "max_transaction_value_exceeded",
        "request_digest": "sha256:edf9dc35873b6b0f0c46f8aeead5193a7dc97bcdecc6116ae68899b75e0e86d6"}}}
    }
  }
}
```

### 8.3 Acceptance and Receipt

An acceptance is a decision about the request, not a statement about its
outcome. On acceptance the task proceeds (`TASK_STATE_WORKING`), the server
performs the skill, and the task ends in the terminal state the skill reaches:
`TASK_STATE_COMPLETED` when it succeeds, `TASK_STATE_FAILED` when it does not.
A skill that fails after an acceptance MUST NOT be reported as
`TASK_STATE_REJECTED`, and a rejection (Section 8.2) MUST NOT be reported as
`TASK_STATE_FAILED`: the two states answer different questions.

The server MAY put a verification receipt as `result` in `Task.metadata[URI]`.
A server that does so MUST put it there before it invokes the skill and MUST
leave it in place whatever terminal state the task reaches, so that a failed
task still shows that it was authorized. All members are REQUIRED unless marked
otherwise:

| Member | Type | Meaning |
| :-- | :-- | :-- |
| `verdict` | string | `"ACCEPT"` |
| `draft` | string | The AAE revision verified against. |
| `steps_passed` | array of integers | The -02 §5 steps run, e.g. `[1,2,3,4,5,6,7]`, plus 8 and 9 where they applied. |
| `aae_id` | string | The VC `id` of the presented AAE. |
| `issuer` | string | The root issuer (Section 7.5). |
| `subject` | string | `credentialSubject.id`. |
| `skill`, `action` | string | The gated skill and its mapped action. |
| `verified_at` | string | RFC 3339 UTC time of the decision. |
| `request_digest` | string | The request part the decision was made on (Section 8.5). Present in every receipt, whether or not grants were evaluated. |
| `request_uri` | string | OPTIONAL. An `https` URL from which a party entitled to it can retrieve the request part. It is a retrieval path only: whoever dereferences it MUST recompute `request_digest` over what it retrieved and MUST NOT rely on content that does not match. |
| `enforce` | object | OPTIONAL; present when grants were evaluated: `{"verdict", "core", "core_digest"}` (-02 §2.5.3), so the client or an auditor can recompute the decision. |
| `ratification` | object | Present when a ratification closed a hold (Section 7.6): `{"status", "decision", "authority", "core", "core_digest"}` (-02 §6.3). `enforce` then carries the PENDING record it ratifies. |

Without grant evaluation, `enforce` is absent, and without `request_digest`
two receipts under the same AAE and skill would differ only in `verified_at`.
`request_digest` is what lets an auditor who holds a request show that a
receipt was issued for it. It identifies content, not an execution: two tasks
with byte-identical request parts carry the same `request_digest`, and the task
`id` (A2A §4.1.1) tells the executions apart.

This profile leaves the form of both identifiers in a receipt open. The server
mints the task `id`; it MUST differ from every other task id the server has
issued and MAY be random, sequential or derived. The issuer chooses the VC
`id`, which the receipt carries as `aae_id`; it MUST be a URI that names one
AAE and no other. A client or auditor MUST NOT draw any conclusion from the
form of either value beyond its identity: equality of two task ids means one
execution, equality of two `aae_id` values means one envelope.

A receipt is a statement by the server. It is not signed by this version of
the profile; a server MAY additionally sign it, for example as a JWS in an
artifact.

The paired case, under one AAE capped at 500 EUR:

- A request for 80 EUR passes steps 1-7. The receipt is written, the skill is
  invoked, and the item is not in stock. The task ends in `TASK_STATE_FAILED`,
  `Task.metadata[URI].result` is the ACCEPT receipt, and the status message
  states the skill's failure.
- A request for 900 EUR fails at step 7. The task ends in
  `TASK_STATE_REJECTED` with the result of Section 8.2, and the skill is never
  invoked.

```json
{
  "id": "t-7", "contextId": "c-7",
  "status": {
    "state": "TASK_STATE_FAILED",
    "message": {"role": "ROLE_AGENT",
      "parts": [{"text": "place-order failed: not in catalogue: DESK-02. The AAE was verified."}]}
  },
  "metadata": {"https://moltrust.ch/extensions/aae/v1": {"result": {
    "verdict": "ACCEPT", "draft": "draft-kroehl-agentic-trust-aae-02",
    "steps_passed": [1, 2, 3, 4, 5, 6, 7],
    "aae_id": "urn:uuid:6604de88-5d47-49c3-a20b-5f00224c3b5f",
    "issuer": "did:web:registry.example", "subject": "did:web:buyer.example",
    "skill": "place-order", "action": "pay",
    "verified_at": "2026-10-28T15:04:05Z",
    "request_digest": "sha256:97ff82c176abd81ff1260c0885e3e25c2e651f153c6f4bcb8c6263e77d55198b"}}}
}
```

The digest above is that of the request part
`{"skill": "place-order", "transaction": {"amount": 80, "currency": "EUR", "items": [{"sku": "DESK-02", "qty": 1}]}}`.

### 8.4 Reason Codes

`reason_code` values are lowercase snake_case. A server MAY use codes not
listed here; a client MUST treat an unknown code as a rejection at the stated
step.

| Step | Codes |
| :-- | :-- |
| 0 | `extension_not_activated`, `skill_not_gated`, `issuer_not_accepted`, `no_pending_challenge` |
| 1 | `malformed_jws`, `malformed_header`, `alg_not_eddsa`, `crit_not_supported`, `kid_not_did_url`, `did_unresolvable`, `verification_method_absent`, `vm_not_authorized_assertionMethod`, `key_not_ed25519`, `invalid_signature`, `signing_authority_mismatch` |
| 2 | `payload_not_json`, `cty_not_aae_json`, `payload_not_object`, `embedded_proof_present`, `missing_id_or_issuer`, `missing_credentialSubject`, `missing_aae_blocks`, `mandate_actions_invalid`, `constraints_not_object`, `validity_not_object`, `validity_not_before_invalid`, `validity_not_after_invalid`, `validFrom_invalid`, `single_use_not_boolean` |
| 3 | `not_yet_valid_not_before`, `expired_not_after` |
| 4 | `challenge_response_missing`, `challenge_response_malformed`, `challenge_response_crit_present`, `challenge_response_unencoded_payload`, `challenge_response_alg_not_eddsa`, `challenge_response_is_envelope`, `challenge_kid_invalid`, `subject_mismatch`, `subject_key_unresolved`, `challenge_signature_invalid`, `challenge_payload_members`, `nonce_malformed`, `nonce_not_authentic`, `nonce_expired`, `nonce_not_issued_for_task`, `audience_mismatch`, `aae_id_mismatch`, `iat_malformed`, `iat_in_future`, `iat_too_old`, `nonce_replayed` |
| 5 | `single_use_already_consumed` |
| 6 | `action_not_in_mandate`, `grant_action_verb_mismatch`, `grant_deny`, `grant_pending`, `ratification_disapproved` |
| 7 | `unrecognized_required_constraint`, `constraint_unevaluable`, `currency_mismatch`, `max_transaction_value_exceeded`, `domain_not_in_allowlist`, `rate_limit_exceeded` |
| 8 | `revocation_status_indeterminate`, `revoked` |
| 9 | `ancestors_unbounded`, `ancestor_not_jws`, `ancestor_id_duplicated`, `ancestor_revoked`, `delegation_malformed`, `parent_aae_not_supplied`, `delegation_cycle_detected`, `delegation_recursion_limit`, `delegator_aae_hash_mismatch`, `delegator_did_mismatch`, `delegation_policy_missing`, `delegated_actions_not_subset`, `delegation_depth_inconsistent`, `delegation_max_depth_exceeds_parent`, `delegation_depth_exceeded`, `required_parent_constraint_dropped`, `required_parent_constraint_downgraded`, `unrecognized_constraint_differs`, `delegation_currency_mismatch`, `delegated_constraint_relaxed`, `delegated_allowlist_not_subset`, `delegated_rate_limit_not_narrower`, `delegated_validity_widened`, `delegated_grants_dropped`, `delegated_grant_not_covered` (and the step 1-2 codes, for an ancestor) |

A `PENDING` grant verdict (-02 §6.1) means the mandate defers the action to a
decision not yet made. A server that does not declare `deferred_decisions`
reports it as a rejection (`grant_pending`); one that does holds the task until
a ratification closes it (Section 7.6). `ratification_malformed` is the
`reason_code` of the `InvalidParamsError` of Sections 7.1 item 5 and 7.6.

### 8.5 Request Digest

`request_digest` binds a result to the request part it was decided on.

Input: the request part of the presentation message (Section 6.1), the JSON
object with exactly the members `skill` and `transaction`, as the server froze
it on receiving the presentation message: after the number mapping of Section
6.4 and before the skill runs. Nothing else enters the digest: not the AAE, not
`ancestor_jws`, not the challenge or its nonce, not the task id, not text
parts. The challenge-response message cannot change the request (Section 6.3),
so every result on a task reports the same digest.

Computation: serialize the input with the JSON Canonicalization Scheme
(RFC 8785) to UTF-8 octets, and compute SHA-256 over those octets with no
prefix and no domain-separation tag. The value is the string `sha256:`
followed by the 64-character lowercase hexadecimal encoding of the hash, 71
characters in all, the same form as `core_digest` (-02 §2.5.3).

Verification: a party holding the request part recomputes the value the same
way and compares the strings. A party holding a different serialization of the
same JSON gets the same value, because JCS fixes member order, whitespace,
string escaping and number formatting. A mismatch means the receipt was not
issued for that request.

The nonce of -02 §5 step 4 is left out on purpose. It binds the challenge
response to the task (Section 7.3) and is spent with it; it says nothing a
later auditor of the request needs, and including it would make the digest
impossible to recompute from the request alone. Telling apart two executions of
the same request is the task id's job (Section 8.3).

Test vectors with the request part, the exact JCS octets and the expected
value are in Appendix B and, machine-readable, in
`tests/vectors/request-digest.json` of the reference implementation.

## 9. The Agent's Own AAE

A server MAY publish an AAE issued to its own DID in `params.own_aae`, so that
clients can see under which mandate the server acts. This is informative. A
client can run -02 §5 steps 1-3 on it; it cannot run step 4 from a card,
because a card is not a challenge response, so a client MUST NOT treat an
`own_aae` as proof that the agent it is talking to controls the AAE's
subject. A client that needs that proof can verify the A2A card signature
(A2A §8.4) with a key of the same DID, or ask for a challenge out of band.
`own_aae` is a public document: it MUST NOT contain anything the server would
not publish (Section 11).

## 10. Security Considerations

The security considerations of AAE -02 §7 and of A2A §7 and the extension
topic ("Security") apply. In addition:

### 10.1 Replay

An AAE is presented more than once by design unless `single_use` is set. The
challenge of -02 §5 step 4 is what stops a captured AAE from being used by
anyone who does not hold the subject's `authentication` key, and the
used-nonce store stops a captured challenge response from being replayed.
Section 7.3 binds each nonce to one task, so a response cannot be moved to a
different request. A PERMIT under grants is not single-use (-02 §7.1): where
an action must not be repeated, the server MUST also use `single_use`, an
idempotency key in the `transaction`, or `Message.messageId` deduplication
(A2A §3.3.1).

`request_digest` (Section 8.5) is not a replay defence. It is equal for equal
request parts by construction, so it cannot tell a repeated execution from a
legitimate second order with the same content; an idempotency key placed in
the `transaction` is part of the digest input and does tell them apart.

The used-nonce store and the `single_use` store MUST be shared across all
server instances that can accept the same task or the same AAE (-02 §2.4, §5
step 4). An unavailable store fails closed.

### 10.2 Scope of the Authorization

The server performs exactly the request part of the presentation message. It
MUST NOT read amounts, recipients or actions from text parts, history, or the
challenge-response message. The authorization does not carry over to other
messages on the task (Section 7.4, A2A §7.6.4).

### 10.3 Challenge as a Signing Oracle

A client signs whatever challenge a server sends. Without the checks of
Section 6.3, a malicious server could relay a challenge it obtained from
another relying party and have the client sign it. Because the client signs
only challenges whose `aud` equals the audience in the card it chose to talk
to, and whose `aae_id` is the envelope it presented to that server, such a
relayed response fails condition (d) at the other relying party.

### 10.4 Revocation and Deferred Capabilities

Revocation lookup, ancestor retrieval by URI, outbound DID resolution and
delegated signing authority case (b) are deferred by -02 §5.2. A server that
implements this version rejects in all four cases rather than skipping the
check. Issuers who rely on revocation should keep `not_after` short (-02 §7.1).

### 10.5 Transport and Card Integrity

Production deployments MUST use TLS (A2A §7.1). The `params` in the Agent
Card decide the audience a client signs for and the issuers a server accepts;
a client SHOULD verify card signatures (A2A §8.4) and SHOULD pin the
`audience` it signs for to the interface URL it actually connects to.

### 10.6 Resource Limits

A presentation can make the server parse a JWS, an ancestor chain and a
grant set. The server MUST bound the size of each JWS and the number of
ancestors before verifying them, and MAY set the input limits of -02 §7.9.
Exceeding a limit is a rejection (Section 8.2), not a truncated evaluation.

### 10.7 Unauthenticated Clients and Task Creation

A presentation creates a task in `TASK_STATE_AUTH_REQUIRED` before subject
binding. A server SHOULD limit outstanding challenges per client and SHOULD
expire them with the nonce lifetime. If the server authenticates clients at
the transport level, it SHOULD accept the challenge response only from the
same authenticated client that sent the presentation.

### 10.8 Number Handling

Section 6.4 exists because a conversion layer could otherwise change whether a
value is an integer and so change a `range` predicate's outcome. A server MUST
evaluate the values it actually received after the conversion of Section 6.4
and nothing else.

## 11. Privacy Considerations

-02 §8 applies. An AAE discloses the subject DID, often the principal DID, the
mandate's purpose and its limits to every server it is presented to; a client
SHOULD present an AAE only to servers within its `allowed_domains` and only for
gated skills. Rejection results disclose which check failed; the `enforce`
member discloses transaction values and bounds in the clear (-02 §2.5.2,
§7.8), and the server MUST treat such results like the transaction itself,
including retention. `request_digest` hides nothing: a transaction with few
plausible values (an amount, a currency, a short item list) can be found from
its digest by trying them, so a result carrying it MUST be treated the same
way. Servers SHOULD log the AAE `id`, action, time and outcome
rather than full envelopes (-02 §8). `own_aae` in a public card is published to
everyone.

## 12. IANA Considerations

This document has no IANA actions. A2A has no extension registry at the time
of writing; the extension is identified by its URI (Section 2).

## 13. Conformance

A server conforms to this profile if it implements Sections 4-8 and runs
-02 §5 as specified there. Its -02 §5 implementation SHOULD pass the test
vectors of [MoltyCel/aae-conformance-vectors](https://github.com/MoltyCel/aae-conformance-vectors)
(commit `2f117799c604f258e67d5c13d69fea63881bdae0`, release v1.4.0):

- the 15 native vectors under `vectors/`, which state ACCEPT or REJECT and the
  §5 step at which a rejection happens. They are built against the -00
  revision and use the §5 step numbering that -02 keeps; facts a static vector
  cannot reproduce (step 4, revocation responses, consumed ids) are supplied
  in each vector's context;
- the enforce vectors under `vectors/enforce/` with kernel `enforce_check`,
  built against -02, which fix the verdict and the -02 §2.5.3 core digest for
  grant evaluation;
- for a server that declares `deferred_decisions`, the enforce vectors with
  kernel `ratify`, which fix the status and the core digest of the -02 §6.3
  ratification record and the caller errors of -02 §6.4.

Its `request_digest` implementation MUST reproduce the values of Appendix B.

The reference implementation in this repository runs both sets in CI. A client
conforms if it implements Sections 5, 6 and the client checks of 6.3.

## 14. Implementation Notes (non-normative)

The reference implementation (`aae_a2a/`) uses the A2A Python SDK `a2a-sdk`
1.2.2 with the JSON-RPC binding. The SDK reads `A2A-Extensions` into
`ServerCallContext.requested_extensions` but does not echo activated
extensions in the response; the reference server adds the header with an ASGI
middleware.

The URI `https://moltrust.ch/extensions/aae/v1` is already listed in the Agent
Card at `https://api.moltrust.ch/.well-known/agent-card.json`, with
`params` that predate this profile. That card adopts this profile when its
`params` carry the members of Section 4; clients ignore the members they do
not know (Section 4).

## Appendix A. JSON-RPC Exchange

Presentation:

```http
POST /a2a/jsonrpc HTTP/1.1
Host: supplier.example
Content-Type: application/json
A2A-Version: 1.0
A2A-Extensions: https://moltrust.ch/extensions/aae/v1

{"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
 "params": {"message": {
   "messageId": "m-1", "role": "ROLE_USER",
   "extensions": ["https://moltrust.ch/extensions/aae/v1"],
   "parts": [{"data": {"skill": "place-order",
                       "transaction": {"amount": 120, "currency": "EUR"}}}],
   "metadata": {"https://moltrust.ch/extensions/aae/v1": {"aae": "<compact JWS>"}}}}}
```

Challenge:

```http
HTTP/1.1 200 OK
A2A-Extensions: https://moltrust.ch/extensions/aae/v1

{"jsonrpc": "2.0", "id": 1, "result": {"task": {
  "id": "t-1", "contextId": "c-1",
  "status": {"state": "TASK_STATE_AUTH_REQUIRED",
    "message": {"messageId": "m-2", "role": "ROLE_AGENT",
      "parts": [{"text": "Prove control of credentialSubject.id"}],
      "extensions": ["https://moltrust.ch/extensions/aae/v1"],
      "metadata": {"https://moltrust.ch/extensions/aae/v1": {"challenge": {
        "nonce": "9f2c...e1.1793020000.Q2xh...",
        "aud": "https://supplier.example/a2a/jsonrpc",
        "aae_id": "urn:uuid:6604de88-5d47-49c3-a20b-5f00224c3b5f"}}}}}}}}
```

Challenge response:

```http
POST /a2a/jsonrpc HTTP/1.1
A2A-Extensions: https://moltrust.ch/extensions/aae/v1

{"jsonrpc": "2.0", "id": 2, "method": "SendMessage",
 "params": {"message": {
   "messageId": "m-3", "role": "ROLE_USER", "taskId": "t-1", "contextId": "c-1",
   "extensions": ["https://moltrust.ch/extensions/aae/v1"],
   "parts": [{"text": "AAE challenge response"}],
   "metadata": {"https://moltrust.ch/extensions/aae/v1": {
     "challenge_response": "<compact JWS over {nonce, aud, iat, aae_id}>"}}}}}
```

Result, after an acceptance: a `Task` in `TASK_STATE_COMPLETED`, or in
`TASK_STATE_FAILED` if the skill fails, with the ACCEPT receipt of Section 8.3
in `metadata` either way. After a rejection: a `Task` in `TASK_STATE_REJECTED`
with the result of Section 8.2, and no skill invocation. For the request part
above, `{"skill": "place-order", "transaction": {"amount": 120, "currency":
"EUR"}}`, both carry the `request_digest` of vector B.4.

## Appendix B. request_digest Test Vectors

Each vector gives the request part, the RFC 8785 serialization that is hashed
(the exact UTF-8 octets, shown as text), and the value of Section 8.5.

B.1 The request part of the Section 6.1 example.

```
request part:
{"skill": "place-order", "transaction": {"amount": 120, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}}
JCS octets (UTF-8):
{"skill":"place-order","transaction":{"amount":120,"currency":"EUR","items":[{"qty":20,"sku":"PAPER-A4"}]}}
request_digest:
sha256:84559612f1f46ec0a03f8c448905af075ba4edf66e529b15b50f69c85a68b59a
```

B.2 Members out of order, an integral value sent as a double (Section 6.4), a fraction and a non-ASCII string. JCS sorts members by UTF-16 code units and writes 120.0 as 120.

```
request part:
{"transaction": {"note": "Bürobedarf", "unit_price": 6.25, "amount": 120.0, "currency": "EUR"}, "skill": "place-order"}
JCS octets (UTF-8):
{"skill":"place-order","transaction":{"amount":120,"currency":"EUR","note":"Bürobedarf","unit_price":6.25}}
request_digest:
sha256:20673ecb3bc45abe8dd1aa5455aa90397eb769e42f9af1cff56680f4204eb0c1
```

B.3 Same skill as the first case, a different amount: a different digest.

```
request part:
{"skill": "place-order", "transaction": {"amount": 121, "currency": "EUR", "items": [{"sku": "PAPER-A4", "qty": 20}]}}
JCS octets (UTF-8):
{"skill":"place-order","transaction":{"amount":121,"currency":"EUR","items":[{"qty":20,"sku":"PAPER-A4"}]}}
request_digest:
sha256:fd2490962a20b0d8223d69248ffa5f073180e791864295247ed1eed8661f48f9
```

B.4 The request part of the Appendix A exchange.

```
request part:
{"skill": "place-order", "transaction": {"amount": 120, "currency": "EUR"}}
JCS octets (UTF-8):
{"skill":"place-order","transaction":{"amount":120,"currency":"EUR"}}
request_digest:
sha256:7081684b67799fdd4045a25d028f770a8254746ff279dbabb0486bdb7eeb4176
```
