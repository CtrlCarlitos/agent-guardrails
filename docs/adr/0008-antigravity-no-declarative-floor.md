# Antigravity has no declarative permission floor — the hook is the entire boundary

Claude Code carries `permissions.deny/ask` and opencode carries
`permission.bash/read/edit` as a static, glob-based enforcement layer
independent of any hook — the "declarative floor" ADR-0001 relies on so
that a missing or crashed guardrail Engine still leaves *something*
blocking `rm -rf` and secret reads. Antigravity has no equivalent: its
`hooks.json` registration **is** the entire enforcement surface. There is
no separate static permission config to fall back to.

Decision: `AntigravityConfig`'s fragment carries only a `hooks` key, no
`permissions`-shaped key — there is nothing legitimate to put there. This
is accepted as an inherent per-plane limitation, not a design gap in this
project: ADR-0001's "degrade, don't brick" guarantee (Q14) is real for
Claude and opencode and is **not** available for Antigravity. If the
guardrail binary is missing, times out, or crashes when Antigravity calls
it, whatever Antigravity itself does on a failed hook call (documented
platform changelog history mentions timeouts and unrunnable-hook handling
maturing over 2026, but no declarative fallback) is the only remaining
boundary — likely fail-open, unverified. The hooks.json fragment mirrors
the only proven-working Antigravity hooks file on this machine
(takumi-dream's): a named per-guard wrapper (`"guardrail": {"enabled":
true, ...}`) with events directly inside — chosen over an unproven flat
schema for the same reason as the SessionStart shape check in Plan 4b.

## Consequences

- If Antigravity ever adds a declarative permission config of its own, add
  a floor-equivalent to `AntigravityConfig` then — there's nothing to build
  today.
- The install/update pipeline (Plan 6b or a future dotfiles-installer plan)
  should treat "guardrail binary present and correct version" as
  *more* load-bearing for Antigravity sessions than for Claude/opencode
  ones, precisely because there is no floor behind it.
