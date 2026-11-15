# ADR-0038: Agent sessions run under their own scoped GitHub credential

## Status

Accepted (operator ruling, 2026-11-16: bot account; draft's same-account
mechanism corrected after the gh storage-model finding).

## Context

Doctor's credential posture reports two standing warnings on the primary dev
machine: the operator's gh login carries the `workflow` scope, and three gh
accounts are logged in. Every agent session shares that ambient authority:
any process a session spawns can act as the operator, including rewriting
what CI runs. ADR-0021's whole thesis is the reverse — the strongest control
is the credential that simply lacks the authority (#236). #277 tracks the
design.

## Decision (operator ruling, 2026-11-16: bot account)

A **machine ("bot") GitHub account** — e.g. `CtrlCarlitos-agent` — is the
agent sessions' GitHub identity, carrying a **fine-grained PAT** with only:

- **Permissions**: Contents read/write, Pull requests read/write. Nothing
  else — no Actions, no workflow, no administration, no secrets, no org.
- **Repository access**: only the CtrlCarlitos repositories agents work in
  (granted as outside collaborator with write; free on public repositories).
- **Exposure**: a `gh auth login` entry under the bot's username — gh keeps
  one token per (host, username), so a second profile under the operator's
  own username is impossible without replacing their token. Agent sessions
  run `gh auth switch`-ed to the bot; the operator's terminal stays on their
  own login. Never a shell-profile export.
- **Rotation**: single token, revocable in one action; no enrolled device
  beyond the account's own 2FA.

Why the bot account (the original draft recommended a same-account PAT and
was wrong about the mechanism): gh's storage model means identity separation
requires a distinct username; and distinct username buys clean audit
attribution and visible PR authorship — the actual point of #277. The cost
(2FA enrollment, collaborator grants) is one-time and free on public repos.

**Token shape amendment (wiring session, 2026-11-16):** the fine-grained
PAT proved impossible for this topology — GitHub limits fine-grained PATs
minted under a personal account to **that account's own repositories**, so a
collaborator bot cannot reach the owner's personal repos no matter which
permissions are ticked (writes fail with "Resource not accessible by
personal access token"; public reads leak through, masking the limit). The
token is therefore a **classic PAT on the bot with exactly `repo` +
`read:org`** (`read:org` is read-only membership data that `gh auth login`
requires; no `workflow`, no `gist`, no `delete_repo`, no admin scopes).

What that scope set preserves and what it costs, verified live:

- **CI definitions remain untouchable**: workflow-file writes are gated by
  the separate `workflow` scope, which this token does not carry (probe:
  blocked). Verified end-to-end: branch → commit → PR works; workflow-file
  write, repo administration, and org endpoints fail.
- **Repository ceiling moves from the token to the identity**: the token
  reaches everything the bot account can (the repos it was invited to as
  collaborator), not a hand-picked subset. The practical ceilings are the
  scopes, the repo rulesets (strict required checks, signed commits, no
  bypass actors — the bot must never appear in a bypass list), and audit.
- **Accepted residual (operator ruling, 2026-11-16):** classic `repo` scope
  can reach the Actions **secrets** API — values are write-only and can
  never be read back, but a session could *overwrite* an existing secret.
  Exposure today: exactly two secrets, both in dotfiles
  (`UPDATER_APP_ID`/`UPDATER_APP_PRIVATE_KEY`, consumed by
  `auto-update.yml` — a workflow the bot cannot edit, so a new secret
  cannot be made load-bearing). The residual is accepted with two
  mitigations recorded: overwrites are detectable in the repository audit
  log, and the strict alternative (dropping the bot to read on dotfiles)
  remains available without re-architecting if the exposure ever matters.

## Consequences

- The two credential-posture warnings stop applying to agent sessions; the
  bot's token cannot carry `workflow`, so the class of "agent rewrites CI"
  is structurally closed on the fleet as sessions adopt it.
- The operator's own login is never the credential a session holds.
- Audit logs and PR authorship show the bot account: agent work is visibly
  agent work. The operator's commits remain theirs.
- Bypass-actor rulesets must never include the bot (the #606 delivery
  chain's strict-checks gate depends on nobody bypassing, bot included).

## Wiring runbook (executed in the operator's session)

1. Operator mints the PAT at github.com/settings/personal-access-tokens with
   the permissions above.
2. `gh auth login` with the token as a second account on github.com;
   `gh auth switch` selects it for agent contexts only.
3. Per-plane exposure decision (this ADR's open item): opencode plugin
   environment, claude/codex/agy session env — each plane gets the switched
   profile, never the raw token in config files an agent can read.
4. Acceptance probes (all verified live in the wiring session): branch →
   commit → PR as the bot succeeds; workflow-file write, repo admin, and
   secret *reads* fail; the secrets-API residual is recorded above.
5. `guardrail doctor` posture: the operator's own login keeps its warnings
   (correct — that login still carries them); agent sessions run as the
   bot identity.
5. This ADR flips to Accepted with the operator's ruling recorded.
