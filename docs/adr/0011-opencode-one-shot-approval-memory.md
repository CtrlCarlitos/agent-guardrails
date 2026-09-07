# OpenCode asks use one-shot approval memory

OpenCode's `tool.execute.before` extension point can only return normally or
throw. Its `permission.asked` and `permission.replied` events are observers;
they do not let this Adapter create a native permission request or correlate a
reply to an Engine Verdict. ADR-0007 therefore rendered an Engine `ask` as a
throw telling the model to ask the user and retry, but an identical retry still
produces the same `ask` and can never execute.

Decision: for every OpenCode pre-execution tool call, not only Bash, the Engine
will use one-shot **approval memory** in the existing per-session state. The
first `ask` stores a pending entry and still throws. The Adapter message is:

> guardrail needs confirmation — &lt;reason&gt;. Ask the user; if they approve,
> re-run this exact tool call.

If the same OpenCode session submits the same normalized tool and canonical
arguments from the byte-for-byte same CWD within ten minutes, normal policy
evaluation runs again. A current `deny` remains a Deny and consumes any matching
entry. A current `allow` remains an Allow and consumes any matching entry. A
current `ask` with the same Rule ID atomically consumes the entry and becomes a
single Allow, audited with `rule_id:"ask-approved-by-retry"` and the original Ask
Rule ID in `origin_rule_id`. A later replay asks again and creates a new pending
entry.

The approval key is SHA-256 over a versioned, length-prefixed tuple of the
native session ID, Adapter-supplied CWD, normalized tool name, and canonical
tool arguments. Canonicalization uses a deterministic encoding of the native
argument payload; object key order is irrelevant, array order and scalar values
are preserved, and Bash command bytes remain exact. Length prefixing prevents
tuple-boundary collisions; the state file stores neither the raw arguments nor
the raw session ID. The entry stores the originating Ask Rule ID and expiry. A
changed session, CWD, tool, canonical arguments, or Rule ID cannot consume it.
Missing identity fields, expired state, or session transaction failure preserve
the Ask. When the current Verdict is Ask but the matching entry is expired or
names a different Rule ID, the current Ask replaces that entry with a fresh
ten-minute pending entry; stale approval can never become consumable after a
later policy change.

Approval memory extends M-7's session state and uses its single exclusive
cross-process transaction for load, expiry, evaluation, consume-or-record, and
save. It does not add a JavaScript cache, another file, or another lock domain.
Concurrent identical retries therefore have one consumer: one becomes Allow,
while the next asks and records a fresh entry. NF-13 implementation must wait
until M-7's transaction exists.

## Considered alternatives

- Always Deny an Engine Ask. This preserves enforcement but turns every
  waivable or ambiguous operation into a hard block on OpenCode.
- Return Allow for an Engine Ask. This removes all confirmation value.
- Infer approval from one exact retry. This preserves a useful stop-and-confirm
  workflow without pretending OpenCode exposes a native prompt primitive.

## Consequences

- On OpenCode, an Ask is only as strong as the model's honesty about asking the
  user before retrying. A dishonest model can immediately resubmit the exact
  command and consume the entry. This is a deliberate limitation, not a native
  confirmation guarantee.
- Definitive shapes still Deny because policy is evaluated before approval
  memory and a Deny is never downgraded.
- Approval is narrow, short-lived, and one-shot. It cannot authorize changed
  arguments, tool, directory, session, or Ask rule.
- Audit records distinguish inferred approval with
  `rule_id:"ask-approved-by-retry"` and preserve the originating Ask rule in the
  `origin_rule_id` field.
- Planes whose Adapter boundary can render an Engine Ask natively continue to
  do so. This design is specific to OpenCode's extension boundary.
