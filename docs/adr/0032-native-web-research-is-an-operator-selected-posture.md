# Native web research is an operator-selected posture

Accepted for #351. Native search, reading pages, following links, finding text,
and screenshots need to compose for useful research. Strict destination
projection cannot follow opaque host-owned result references, and Codex cannot
turn a hook Ask into a native approval prompt. We therefore let the operator
turn **web-research enforcement** on or off, without disabling Guardrail or
changing shell networking, secret-file, destructive-command or arbitrary MCP
rules. Off is an explicit opt-out of outbound-data and destination enforcement,
not a claim that research has no exfiltration risk.

The setting is machine-scoped Operator config, changed through a terminal and
the existing authenticated approval broker. Overlays cannot set it, commands
from guarded planes cannot change it, and missing, malformed or unknown values
stay strict. The existing WebAuthn/enrollment requirements are not bypassed.

Fresh setup records off as the new installation default only when there is no
existing Guardrail config directory, state directory or legacy integration.
An existing or ambiguous installation stays strict until the operator changes
it. This deliberately distinguishes a fresh default from weakening an upgrade;
absence of a grants file alone is never sufficient evidence. The bootstrap
default is audited distinctly from an authenticated change. This refines
ADR-0030's fresh-install policy without giving an existing installation an
approval-less loosening path.

Strict projection is preserved. Relaxed projection recognizes a bounded set
of native research operations, including batches and result references; unknown
operations, malformed arguments and local-file or credentialed URLs do not gain
permission. Context7 remains a separate external integration, not a workaround
or implicit beneficiary of this switch. Host-native restrictions still apply.
