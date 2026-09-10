# Night mode — an operator-declared, time-boxed "never block, still watch" posture

**Status:** design addendum to `2026-09-08-containment-posture-design.md`
(candidate ADR-0013), agreed with Carlitos 2026-09-09. Scheduled as the single
task after the housekeeping merge. Not shell semantics; ADR-0012 does not apply.

## Why

Three times this week "turning the guard off for the night" meant moving the
Claude hook entries to `hooks_disabled`. Each time it had the same defects: it
dropped the *denies* along with the asks (no `rm -rf /` or secret-path backstop
overnight), it blinded the audit log for that plane, it covered one plane only,
and it depended on someone remembering to re-arm it — the Claude plane ran
unguarded for two days because nobody did. The operator wants autopilot on the
host on demand; the guard should offer that as a posture, not as a hack.

## Decision

Night mode is the `contained` rendering with a different trigger and a clock:

- **Rendering.** Under night mode every `ask` Verdict is rendered as `allow`
  and audited as `rule_id:"ask-allowed-by-night-mode"` with the originating
  rule in `origin_rule_id`. Every `deny` stays a `deny`. Nothing else changes.
- **Trigger.** `guardrail night on [--until HH:MM | --for 8h]`,
  `guardrail night off`, `guardrail night status`. `on` without a duration
  defaults to 8 hours. There is no indefinite night mode: the marker always
  carries an expiry, and an expired marker is ignored (the engine reverts to the
  host posture by itself; nothing to remember).
- **Storage.** One marker in the Operator config directory
  (`~/.config/guardrail/night.toml`: `until = <RFC3339>`, `set_by = <hostname:pid>`).
  The engine reads it per call, so it is live on all three planes at once, with
  no `settings.json` edits and no plugin or hook restarts.
- **Visibility.** `doctor` and the Claude SessionStart posture print
  `NIGHT MODE until <time>` as their first line while active. The opencode and
  Antigravity adapters include the same text in the first response of a session
  where they can.
- **Self-protection.** A tool call that invokes `guardrail night …` is denied by
  `P5.self-config` on every plane: the guarded agent cannot change its own
  posture. As a second boundary independent of executable name, `night on` and
  `night off` require stdin to be a terminal; `night status` remains usable
  noninteractively. The operator runs mutating commands from a terminal. The
  marker's directory is already under the self-config deny globs.

## Relation to `contained`

Same rendering, two triggers. `contained` is verified by the environment
(`doctor` preconditions: no secret directories present or mounted, only the
workspace writable, `HOME` inside the box) and has no clock. `night` is declared
by the operator on a host that still holds secrets, so it *must* expire. Both
are `posture` values; a repository cannot set either.

## Out of scope

- Any change to what is a `deny`. Night mode never weakens a deny.
- Disabling the audit log. Night mode is the reason the log matters most.
- Automatic activation (time of day, idle detection). The operator turns it on.

## Effort

One CLI subcommand, one marker file with expiry, one rendering branch shared by
the three adapters (the same shape as NF-15's `force_ask` mapping), the
`P5.self-config` rule for the CLI invocation, the doctor/posture line, tests and
one corpus entry. One SOL task; the usual gate; operator review before merge.
