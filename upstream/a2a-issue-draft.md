# Draft: issue for a2aproject/A2A

Not filed. Text for review.

## Venue

- **Target:** new issue in `a2aproject/A2A`, https://github.com/a2aproject/A2A/issues/new
  (template "Feature Request"; maintainers apply the `extension-proposal` label,
  as on #2355 and #1887).
- **Why an issue and not a PR:** the governance page
  (`docs/topics/extension-and-binding-governance.md`, "Proposal Phase") says a
  proposal starts as an issue in `a2aproject/A2A` with an abstract, the
  motivation, and a technical approach. There is no community registry to add
  an entry to: in #1887 a maintainer answered (2026-06-26) that the docs have
  no place that tracks community extension implementations, and the "List of
  Example Extensions" in `docs/topics/extensions.md` points only at
  `a2a-samples`. A docs PR listing this extension would therefore not match
  how the project works today.
- **What we ask for:** feedback on two protocol questions (below). Not an
  experimental repository; that needs a maintainer sponsor and can follow if
  there is interest.

## Title

```
[Extension Proposal] AAE profile: verify an Agent Authorization Envelope before a skill runs
```

## Body

```markdown
### Is your feature request related to a problem? Please describe.

A2A §7.5 leaves authorization to the server, and §7.6.4 says the meaning and
scope of a credential obtained during `TASK_STATE_AUTH_REQUIRED` must be
defined by the implementation, the issuer, or an extension. For agent-to-agent
calls where the caller acts under a delegated mandate (what it may do, within
which limits, until when), there is no extension that defines how such a
mandate is presented, bound to the caller, checked against the requested skill,
and how a refusal is reported.

### Describe the solution you'd like

An extension profile, identified by `https://moltrust.ch/extensions/aae/v1`,
that carries an AAE (Agent Authorization Envelope,
[draft-kroehl-agentic-trust-aae-02](https://datatracker.ietf.org/doc/draft-kroehl-agentic-trust-aae/02/))
and has the server run the draft's Section 5 verification before the skill
runs. An AAE is a W3C VC secured as an EdDSA compact JWS with MANDATE,
CONSTRAINTS and VALIDITY blocks.

- Agent Card: `capabilities.extensions[]` entry with `params` for the draft
  revision, the challenge audience, a map from skill id to mandate action, and
  optionally accepted issuers, DID methods and the agent's own AAE.
- Activation: `A2A-Extensions`. Data: `Message.metadata[<uri>]`.
- Request: the AAE in metadata plus a single data Part
  `{"skill", "transaction"}`. The server authorizes and executes that part.
- Proof of possession (draft §5 step 4): the server answers with a Task in
  `TASK_STATE_AUTH_REQUIRED` carrying a nonce; the client returns a JWS over
  `{nonce, aud, iat, aae_id}` on the same task. The nonce is bound to the task.
- Outcome: protocol violations are A2A errors (`ExtensionSupportRequiredError`,
  `-32602` with `google.rpc.ErrorInfo`). A failed verification moves the task
  to `TASK_STATE_REJECTED` with the failing Section 5 step and a reason code in
  `metadata[<uri>]`. On success the task proceeds and may carry a receipt.

Spec: https://github.com/MoltyCel/aae-a2a-extension/blob/main/spec/aae-a2a-extension-v1.md
Reference implementation (Python, `a2a-sdk` 1.2.2, Apache-2.0), two agents and
tests, including runs against the public AAE conformance vectors:
https://github.com/MoltyCel/aae-a2a-extension

### Describe alternatives you've considered

- A new RPC method for the challenge: rejected, because §7.6 already provides
  `TASK_STATE_AUTH_REQUIRED` for in-band credential exchange negotiated by an
  extension.
- A single message with a client-chosen nonce: does not meet the draft's
  requirement that the relying party mint the nonce.

### Additional context

We would like maintainer guidance on the use of §7.6. Is
`TASK_STATE_AUTH_REQUIRED` with the challenge in `TaskStatus.message.metadata`
the intended use for an extension-defined credential exchange?

When an extension refuses authorization for a well-formed request, is
`TASK_STATE_REJECTED` with structured metadata preferred over a JSON-RPC error? A2A defines no authorization error code, and
the `-32001..-32099` range is reserved for A2A errors.

Related: #1716 (skill-level authorization), #1937 (binding delegated authority
to a context), #2028 (on-behalf-of delegation payload), #2133 (exact-message
authorization envelope), #1769 (verifier-side permits and receipts), #1887
(where community extensions are listed).
```
