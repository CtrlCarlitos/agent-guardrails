# agent-guardrails — design

Status: confirmed 2026-09-03 via a grilling + domain-modeling session. Terminology in
[CONTEXT.md](./CONTEXT.md); rationale for the load-bearing choices in [docs/adr/](./docs/adr/).

## Problem

Three hand-ported guardrail implementations grown under time pressure with no spec:
Claude Code shell hooks → ported to an opencode JS plugin → ported to an Antigravity
Python hook. The secret-path list is encoded 4×, the sensitive-command list 3×, and
`logEvent` / `truncate` / `isSecretPath` / exit-code interpretation are reimplemented
per language. Goal: one policy, enforced across any number of planes, shipped through
dotfiles.

## Shape

A **hybrid** (ADR-0001): one policy definition produces (1) a shared **Engine** — a Go
static binary, `guardrail`, that holds all decision logic — and (2) generated
**declarative floor** config per plane that the plane enforces natively even if the
Engine is down. Adapters are thin and use each plane's native extension mechanism
(ADR-0002).

## Guardrail Policy

### Core — shipped in the dotfiles package ("useful to any developer")

| # | Policy | Notes |
|---|---|---|
| P1 | Destructive-command gate (Bash PreToolUse) | keep `rm -rf` outside safe roots, `git push -f`, `git clean -f`, docker teardown/prune, `$()`-computed / cross-worktree `docker rm`. Add `dd`/`mkfs`/`wipefs`/`shred` (deny); `truncate`/`:>`/`>` onto tracked file, `chmod -R`/`chmod 777`/`chown -R`, `find -delete` / `-exec rm`, `kill -9`/`killall`/`pkill` (ask); `sudo`/`su`/`doas` (deny) |
| P2 | Git-safety gate | `git reset --hard` → **deny** (today only an ask-glob). `git config` writes + `.git/hooks/**` + `.git/config` edits → **deny** (`core.hooksPath` / `core.fsmonitor` = later RCE). Add `git checkout .` / `restore .`, `git branch -D`, history-rewrite (`filter-repo`, `reflog expire`, `gc --prune=now`, `commit --amend`), `git remote add` / `set-url`, `git stash clear` / `drop`, push to `main`/`master`/`--tags` (ask) |
| P3 | Shell-operator-aware, fail-closed matching (mechanic) | **real tokenizer (`mvdan.cc/sh`)**, not regex. Split on `&& \|\| ; \|` + newlines; every sub-command must pass; strip `timeout`/`time`/`nice`/`nohup`/bare `xargs`/`env VAR=`; do **not** strip `npx`/`uvx`/`docker run`/`make`/`just`/`devbox run` — recurse into what follows. Unmatched → `ask`. Replaces (does not resurrect) the reverted heredoc preprocessor |
| P4 | Secret-path denial (read + write + `cat`/`sed`/`grep`) | expand list: `*.pem`/`*.key`/`id_ed25519*`, `~/.config/gcloud`, `~/.kube/config`, `~/.npmrc`/`.pypirc`, `~/.docker/config.json`, `~/.git-credentials`, `service-account*.json`, `/root/.ssh/**`, `~/.claude.json`. Make the `.env` / `.env.*` / `.env.example` glob consistent across planes. Add `env`/`printenv`/`echo $*_TOKEN` (ask) |
| P5 | Filesystem-scope + "runs-later" gate (Edit/Write/redirect) | writes outside the worktree root (ask); symlink-escape — path inside repo resolving outside → deny; CI config (`.github/workflows/**`, `.pre-commit-config.yaml`, …) ask; agent-self-config (`.claude/**`, `CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.envrc`, shell rc) deny; lockfile hand-edits, `Dockerfile`/`Makefile`/`*.tf`/`conftest.py`/`setup.py` (ask) |
| P6 | Network-egress + supply-chain gate | `curl`/`wget`/`nc`/`socat`/`scp` to non-allowlisted host → deny (allowlist via `WebFetch(domain:…)`, not argument-regex); `curl\|sh` family → deny; package installs `pip`/`npm`/`gem`/`cargo`/`go install`/`apt` (ask); registry-redirect `--index-url` / `--registry` / `pip install git+http` (deny) |
| P7 | Prompt-injection hygiene (mechanic) | all `tool_input` / tool output / fetched content / file bodies = untrusted data. In hook code: `jq -n --arg` for model-facing text, never `eval`, `readlink -f` + prefix-check paths. **Lethal-trifecta session gate**: block a turn combining private-data read + untrusted-content ingest + outbound network |
| P8 | Post-edit format + lint, tiered | per-edit (<2s, one file) via PostToolUse; session-completion (exit 2 blocks) via Stop/SubagentStop. Commands per language = a **Recipe** |
| P9 | Audit log | JSONL, mode 0600. **Single global stream**: `~/.local/state/guardrail/audit.jsonl` (Linux/mac), `%LOCALAPPDATA%\guardrail\audit.jsonl` (Windows). Path overridable per-project in `guardrail.toml`. Central rotation / size cap. Secret redaction of logged command text. Alert on repeated denials in one session (possible injection). Fields: `ts`, `session_id`, `plane`, `tool`, `tool_input`, `verdict`, `matched_rule`, `reason` |
| P10 | Autonomy posture | per-plane instruction file: operate autonomously, don't ask conversational permission for routine dev, trust the guard, pause only on an explicit `ask` or genuine ambiguity. Advisory — unenforceable by nature |

### Recipes (P8) — one per language, hard cut

Go, Python, JavaScript/TypeScript, Rust, Elixir, **Odoo** (Odoo is treated as a
language: its Python + OWL/JS + XML toolchain travels as one recipe). Phoenix-only
security tools (`sobelow`, `mix_audit`) ride in the Elixir recipe's session tier.
Anything else: the project defines it in its Overlay. Indicative commands (from
research, see the dotfiles repo's research notes):

- **Go**: per-edit `gofmt -w` + `go vet ./<pkg>/`; session `go build ./... && go test ./... && golangci-lint run && govulncheck ./...`
- **Python**: per-edit `ruff format <f>` → `ruff check --fix <f>`; session `ruff check . && mypy . && pytest`
- **JS/TS**: per-edit `prettier --write <f>` + `eslint --fix <f>` (or `biome check --write <f>`); session `tsc --noEmit && eslint . && <test>`
- **Rust**: per-edit `rustfmt <f>`; session `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test`
- **Elixir**: per-edit `mix format <f>` + `mix credo <f> --format json`; session `mix compile --warnings-as-errors && mix test`, CI `mix dialyzer` + `mix sobelow --exit` + `mix deps.audit`
- **Odoo**: per-edit `*.py` → `ruff format` → `ruff check --fix` → `pylint --load-plugins=pylint_odoo -d all -e odoolint`; `*.js` → `eslint --fix` (does Prettier + OWL rules); `*.xml` → `xmllint --noout` then `xmllint --noout --relaxng import_xml.rng`; session full `pylint`, `oca-odoo-pre-commit-hooks`, `odoo -d test --stop-after-init --test-enable -i <module>`
- Wrap reformat-then-nonzero formatters as "format then re-check, fail only on real errors."

### Overlay — a project's committed `guardrail.toml`, NOT shipped

- **P11 SQL-mutation guard**: block `psql DROP/DELETE/TRUNCATE/UPDATE/ALTER`, `dropdb`,
  `createdb` unless the target DB matches the project's ephemeral pattern. Core
  provides the mechanism; the project supplies the pattern.
- **Docker-container-naming scheme**: so the P1 docker guard matches real container
  names, not just sibling git-worktree basenames.
- **P12 per-worktree scoped-config generation**: a generator emits per-worktree
  `additionalDirectories` / `external_directory` / `writable_roots` at worktree
  spin-up. Project-shaped; "later".
- Anything referencing `tk` / `takumi` / Odoo-customers / worktree-DBs → belongs in
  **takumi-dream**, never here.

### Deletions / non-adoptions

- Do not resurrect the heredoc preprocessor (P3 tokenizer replaces it).
- No argument-constraining URL regex (`curl http://host/*`) — deny the tool, allowlist
  via `WebFetch` domain.
- Drop `antigravity-guard.py`'s hand-copied `SENSITIVE_PATTERNS` — P3 makes it a
  generated artifact.

### Known gaps to track (not necessarily fixed in v1)

`docker … | xargs docker rm -f` bypass; multi-line `git -C`; unverified subagent /
`task`-tool interception on opencode (OpenCode #5894).

## Planes & adapters

- **Engine subcommands** for command-hook planes: `guardrail hook claude` (stdin JSON;
  block via exit 2 or `hookSpecificOutput.permissionDecision`), `guardrail hook
  antigravity pre|post` (stdin `{toolCall,…}` → stdout `{decision,reason}`),
  `guardrail hook codex` (later).
- **opencode**: a ~30-line JS plugin (`adapters/opencode/`) that `spawnSync`s
  `guardrail hook opencode` and maps the result to `throw` / allow. opencode's
  declarative `permission` block in `opencode.json` is the real boundary; the plugin
  is defense-in-depth.
- Events: `PreToolUse` (gate), `PostToolUse` (format/lint), `Stop` /
  session-completion (full suite + secret scan).
- Plane event/decision reference:
  - Claude: `PreToolUse`/`PostToolUse`/`Stop`/`SubagentStop`/`SessionStart`; block =
    exit 2 or JSON.
  - Antigravity: `PreToolUse`/`PostToolUse`/`PreInvocation`/`PostInvocation`/`Stop`;
    decisions `allow|deny|ask|force_ask|deny_unless_prior_grant`; 30s default timeout.
    Global hooks: `~/.gemini/config/hooks.json`. Project: `<repo>/.agents/hooks.json`.
    The `agy` CLI and the Antigravity IDE both run hooks (confirmed on this machine).
  - opencode: in-process plugin (`tool.execute.before/after`, `permission.ask`,
    `event`) + a limited config `experimental.hook` (`file_edited`,
    `session_completed`, argv array).

## Distribution & install

- **Separate `agent-guardrails` repo** with its own CI (ADR: repo boundary).
- CI runs the test matrix, then on a version tag cross-compiles
  Linux/macOS/Windows × amd64/arm64 → GitHub Releases (goreleaser or a `go build`
  matrix + `gh release upload`). **Release only when the matrix is green.**
- Dotfiles installer: a new gated, idempotent function in
  `run_onchange_install_packages.sh.tmpl` (+ `.ps1.tmpl` inline), plus the
  `~/scripts/update_ai_tools.sh` twin. Fetches the **pinned** release asset →
  `~/.local/bin/guardrail`, verifies checksum + `guardrail version`; `Unblock-File`
  sweep on Windows. Version pinned in the installer template like
  `ANTIGRAVITY_VERSION`; bump = a dotfiles commit → `chezmoi apply` → `run_onchange`
  re-fires. `run_onchange` no-ops when the installed version already matches.
- No on-machine compilation. No Go or Docker dependency on guard machines. Container
  build (`docker run --rm -v $PWD:/src -w /src golang:1.23 go build ./...`) is a
  contributor convenience only.
- Per-plane wiring: `jq`-merge the hook/plugin registration + the generated
  declarative floor into `~/.claude/settings.json`, `~/.config/opencode/opencode.json`,
  `~/.gemini/config/hooks.json` (created if absent). All three planes guarded globally.
- `guardrail sync` (run inside a repo): regenerate that repo's project-level plane
  configs from Base + Overlay, for projects that want Overlay rules mirrored into the
  Declarative floor too. Most projects don't need it — the Engine enforces Overlays at
  runtime regardless.

## Config & failure behavior

- `guardrail.toml` discovered from `git rev-parse --show-toplevel`; `GUARDRAIL_CONFIG`
  override for non-git dirs and tests. Committed or gitignored is the project's call.
- Merge: Base, then Overlay. Overlay **adds** rules, **fills slots** (safe roots,
  egress hosts, ephemeral-DB pattern, container scheme, formatter tiers, audit-log
  path), and may `waive = ["P6"]` a named rule — logged on every hit + printed in the
  session-start banner. No silent `deny` → `allow` (ADR-0003).
- Versioning: installer pins an exact release; `guardrail.toml` sets
  `engine_min_version`; the Engine **warns** (does not block) when the binary is
  older. No auto-update.
- Engine missing / errors / times out → **degrade, don't brick**: dynamic checks
  (tokenizer, trifecta, symlink resolution) are lost; the Declarative floor still
  denies `rm -rf` / secret reads / non-allowlisted egress; the session-start banner
  reports the Engine is down.

## Testing

- **Contract fixtures** (`test/fixtures/`, the bulk, in CI): recorded real payloads
  per plane → assert Verdict + emitted native response.
- **Smoke suite** (thin, a `just` target, run in the devcontainer): launch each real
  agent, one known-`deny` + one known-`allow`, assert blocked / allowed.
- Both green on Claude + opencode + Antigravity gates a version-pin bump.

## Build order

1. Engine core (policy model, merge, `mvdan.cc/sh` tokenizer, verdict) + `guardrail
   hook claude` (richest API → reference) + contract fixtures.
2. Declarative-floor generation for Claude; dotfiles installer function; smoke test.
3. opencode adapter (plugin + `guardrail hook opencode` + `opencode.json` generation).
4. Antigravity adapter (`guardrail hook antigravity` + `~/.gemini/config/hooks.json`
   generation).
5. Recipes beyond Go.
6. Hand Carlitos instructions to point takumi-dream at the package (he runs it),
   keeping only its Overlay: `tk` allowlist, Odoo worktree/DB rules, container naming,
   P11 pattern, P12 generator.
7. Codex adapter when adopted.

## Open follow-ups (outside this design)

- Skills-path confusion for Antigravity: `skills` CLI writes `~/.agents/skills/`, but
  Antigravity docs say it reads `~/.gemini/config/skills/`; superpowers / mp ship
  skills inside their plugin trees. Separate investigation.
