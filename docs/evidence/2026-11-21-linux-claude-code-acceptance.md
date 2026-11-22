# Linux Claude Code acceptance and real-session verdicts

## Claim

On Linux, the Claude Code lifecycle passes the isolated acceptance run, and this host's audit log holds `ask` and `deny` verdicts returned to real Claude Code sessions; the harness's own nested `claude -p` stage was not authenticated and is not part of the claim.

## Context

- Guardrail: `381e8ee` with the #92 Claude Code adapter, built as `v0.0.1-accept` and `v0.0.2-accept`. The host's installed binary is `v0.23.46-dev`, installed 2026-11-20 06:25; audit records carry no version, so the binary behind the 2026-11-16 session is not known
- Runtime / plane: Claude Code `2.1.330` on `PATH`; the recording session started under `2.1.328`
- OS / shell: Linux `7.0.0-43-generic` x86_64 / zsh
- Times are UTC. The runs below are dated 2026-11-22 UTC (2026-11-21 local).

## Method

```sh
python3 -B test/acceptance/harness.py --host claude --report <scratch>/claude-hermetic.json
python3 -B test/acceptance/harness.py --host claude --live --report <scratch>/claude-live.json
guardrail selftest --evidence claude
```

The real-session counts come from the host audit log
(`~/.local/state/guardrail/audit.jsonl`): `plane: claude`, `event: pre`
records grouped by session ID, keeping only UUID-shaped session IDs. Command
text was not read out. The counts are a snapshot taken at 01:59.

## Observation

Both acceptance runs exited 0 with no failed stage.

```json
{"pass": 13, "fail": 0, "unsupported": 0, "operator_assisted": 2, "skipped": 1, "total": 16, "overall_pass": true}
{"pass": 13, "fail": 0, "unsupported": 0, "operator_assisted": 3, "skipped": 0, "total": 16, "overall_pass": true}
```

Selected stage observations from the `--live` report:

```text
host_hook_trust         selftest exit=0, live-evidence gate exit=1 not-yet-observed=True; claude settings: guardrail hook registered but NEVER OBSERVED FIRING
harmless_deny           Bash cat .env: exit=2 audit=deny/P4.secret-path; Read .env: exit=2 audit=deny/P4.secret-path; Bash cat allowed.txt: allow
host_ask                hook exit=0, permissionDecision=ask, audit=ask/P1.chmod, retry guidance=True
approval_retry          initial=deny/P6.egress, grant hook=ask/operator-action-ask, grant cli exit=0, overlay and operator config persisted=True, retry fetch=allow, replay exit=2, host-ask audit=2
fixture_evidence_gate   7 fixture pre-hook records in the window, live-evidence gate exit=1 not-yet-observed=True
disablement             disable exit=0, guardrail hooks removed=True, user hook preserved=True, user settings preserved=True; claude: present, hook NOT registered
recovery                recover without a terminal exit=2, terminal recover exit=0, byte-identical backup=True, hooks restored=True
live_runtime_mediation  operator_assisted: isolated Claude Code runtime is not logged in (session reported=True)
cleanup_isolation       real home unchanged=True, temp cleaned=True
```

These stages feed synthetic envelopes to the installed hook. No tool ran in
them, so they show the verdict a host would receive. In `approval_retry` the
harness claims the approval ticket itself; no operator answered the ask.

The nested runtime started and reported a session ID, then answered
`Not logged in`. No tool call was made, so `live_runtime_session_observed`
stayed `false` and every audit record in the report is labelled
`synthetic_fixture` or `harness_driven_lifecycle`.

Real sessions on this host, from the audit log (all three UUID-shaped
sessions it holds):

| Session | Window | Pre-hook verdicts |
|---|---|---|
| `8d1d952f-d12e-481b-9c85-cb8e4b08e16a` | 2026-11-16 00:44 to 01:20 | 78 `allow`; 10 `ask`, all `Bash` (`P3.unresolved` 6, `P1.out-of-repo-write` 2, `P2.gh-pr-merge` 1, `P2.git-branch-delete` 1); 1 `deny`, `Bash` (`P5.self-config`) |
| `06146113-2568-492f-b43d-a4cd3909fe9e` | 2026-11-22 01:42 to 01:59 | 133 `allow`; 4 `deny`: `Bash` 3 (`P5.self-config` 2, `host-auto-ask-escalated` from `P4.credential-print` 1), `Edit` 1 (`host-auto-ask-escalated` from `P5.ci-infra-lockfile`) |
| `9794fd18-c1de-41ab-87e5-4ba5904d125e` | 2026-11-22 01:47 to 01:47 | 22 `allow` (`Bash`, `Read`); no `ask` or `deny` |

Every `ask` is a `Bash` call. The denials are `Bash` and one `Edit`. `Read`,
`Write` and `Skill` calls reached the hook and were allowed; none was asked
or denied.

The second session is the one that wrote this record, and it includes the
calls of the review subagent it started. Its denials were seen from inside
the session: the tool call returned the denial text and did not run. It ran
in an auto permission mode, where ADR-0035 turns an ask into a deny, so it
has no `ask` records. The third session was another session on this host
and is not attributed here.

```text
binary mtime cutoff: 2026-11-20T06:25:16.18576699Z
segments=1 records=1889 claude=404 synthetic=84 stale=89 rejected=72 duplicates=20 malformed=0 eligible=139 sessions=2 qualifying_sessions=2
claude: live mediation observed (heuristic); the registered hook is running
```

The gate counts only records newer than the installed binary. Its two
qualifying sessions are the second and third rows. The 2026-11-16 session,
the only one with `ask` verdicts, is the `stale=89` and did not open the
gate.

## Consequence

The compatibility matrix records Linux Claude Code as enforced and observed,
on the audit-log standard its `Enforced, observed` state defines: real
sessions sent tool calls to the hook and got `ask` and `deny` verdicts back.
The `ask` verdicts come from one session under an unrecorded Guardrail
version. It is a heuristic that the hook ran, with no coverage claim. An
authenticated `--live` run of the harness and an operator answering a native
permission prompt are still open.

## Links

- Issue / ADR: #92, ADR-0033, ADR-0035
