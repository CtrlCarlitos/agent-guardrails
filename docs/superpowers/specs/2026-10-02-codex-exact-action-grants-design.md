# Exact-action approvals for Codex (#349)

The operator approved the proposal in this session. Codex cannot surface a
policy Ask as a native approval prompt. A blocked command or patch must instead
leave a private, durable request whose full action the operator can review.
Chat text never authorizes a retry. PostToolUse feedback never authorizes or
prevents an edit that already ran.

## Contract

Only pre-execution Codex Asks for supported commands and parsed patches are
eligible. Deny and policy.NeverGrantable remain invariant. The exact binding is
plane, session, repository, working directory, canonical tool, rule, action kind,
full command or patch text, and every projected path. SHA-256 covers a canonical
JSON encoding, with no command or patch whitespace normalization.

The hook records the request in an owner-only directory under Operator config,
outside the repository. Full input stays there, never in the redacted audit log
or Overlay. An identical pending retry reuses the request without extending its
15-minute expiry. Stores are bounded; failures retain the original Ask.

The guidance names `guardrail approvals grant --record <id>`. This requires a
real operator terminal. Prompt mode shows the complete action and quoted text,
then requires `yes`. Passkey mode uses the existing broker and authenticator
requirements; its ceremony shows the same full action. A broker request carries
only the record identity and digest; completion revalidates both before issuing
authorization. There is no new daemon operation that approves via IPC.

Approval authorizes one identical retry. Consumption, revocation, expiry and
issuance share a filesystem lock. A mismatch spends nothing. A match is spent
durably before Allow; an audit failure keeps the Ask and leaves it spent.
`guardrail approvals revoke --record <id>` revokes a pending or approved action.
Existing command grants remain compatible.

## Verification

Test exact matching, changed patches and paths, different repositories and
sessions, expiry, concurrent single-use consumption, private-store validation,
decline, terminal requirements, passkey enrollment, excluded rules and Deny.
Use real Windows and Linux Codex sessions with a loopback provider to demonstrate
blocked-before-edit, approved identical retry, changed retry rejection, and
post-edit recipe feedback with file snapshots. Hook timeout or missing dispatch
is an inconclusive run, never evidence of blocking or coverage.
