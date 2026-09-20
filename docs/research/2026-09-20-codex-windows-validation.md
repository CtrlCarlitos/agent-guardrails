# Codex Windows validation — 2026-09-20

Environment: Microsoft Windows NT 10.0.26200.0, PowerShell 7.6.6, Codex CLI
0.154.0, and installed Guardrail v0.21.6-dev. The repository was at `8cb12ca`
for the final documentation pass. No production secret was used.

## Installer and generated command

The installed dotfiles command completed successfully against the real user
configuration:

```powershell
guardrail gen-config codex --merge "$env:USERPROFILE\.codex\hooks.json" `
  --binary "$env:USERPROFILE\.local\bin\guardrail.exe"
```

The target was `C:\Users\carlitos\.codex\hooks.json`. Its SHA-256 was
`BB745C885AC333116D135CECBDFD4B2DDBB337220A0B3B00E500D03E687C6A21`
both before and after the merge, establishing an idempotent installed run.

The installed generator still emitted only the POSIX `command`. Replaying that
handler through Codex's Windows `cmd.exe /C "<handler>"` launch shape exited 1
with no hook JSON. The `commandWindows` implementation in PR #141 uses an
encoded PowerShell payload and a `cmd.exe` exit-2 fallback. The same exact
launch-shape control accepted hook stdin and returned Guardrail's allow JSON
with exit 0. This establishes that the generated Windows handler can run; it
does not establish that Codex dispatches a hook for a tool path.

## `/hooks` trust

Codex discovered the user hook from `~\.codex\hooks.json`. After the handler
content changed, `/hooks` showed Review needed and zero active handlers. The
operator used the `t` trust action; `/hooks` then showed the handler Active and
Trusted. Trust remained separate from registration and was keyed to the
reviewed content. The first-use review step therefore behaves on Windows as the
documented trust model requires; an installer must not claim that generation
alone activates enforcement.

## Real session and evidence gate

Interactive session `01a0bdf1-c225-7f00-a953-948169271bd7` ran four harmless
PowerShell-backed shell calls (`Get-Location`, `Get-Date`, and two distinct
`Write-Output` canaries). Two calls were made after `/hooks` showed the handler
Active and Trusted. The Codex rollout recorded all four `functions.exec` calls,
but the default Guardrail audit contained no matching live-session records.

The post-session command was:

```powershell
guardrail selftest --evidence codex
```

It exited 1 and reported:

```text
segments=1 records=3314 codex=99 synthetic=97 stale=2 rejected=0 duplicates=0 malformed=0 eligible=0 sessions=0 qualifying_sessions=0
codex: live mediation not yet observed; approval-proposal gate remains closed
```

The counts include concurrent synthetic test traffic; the decisive values are
zero eligible records and zero eligible sessions after the binary-mtime cutoff.
This result does not unblock the approval-flow ADR. It is consistent with
[openai/codex#24453](https://github.com/openai/codex/issues/24453), where the
Windows `command_execution` path bypasses `PreToolUse` even with matcher `*`.

## `write_stdin` and hosted tools

A Windows code-mode control started `cmd.exe /q /k`, then sent non-empty input
through `write_stdin` to create a disposable canary and sent `exit`. The file
contained `codex-windows-stdin-fixture`; no Codex audit record appeared in the
five-minute observation window. Because the parent Windows execution also had
no pre-hook, this run cannot isolate the later-input gap from the broader
Windows dispatch gap. Its end-to-end effect is at least as weak as the Linux
finding: bytes can reach an interactive process without a Guardrail verdict.
The independent Linux reproduction and requested contract remain
[openai/codex#46372](https://github.com/openai/codex/issues/46372).

Hosted-tool behavior is platform-independent in the official hook contract:
provider-hosted tools do not pass through local command hooks. No hosted result
was fabricated as a Windows enforcement test. The required no-unmediated-
fallback contract remains [openai/codex#46373](https://github.com/openai/codex/issues/46373).

## Conclusion

Windows hook discovery, review, and hash trust work. The installed merge is
idempotent, and the corrected Windows command can consume hook stdin when
invoked. Live mediation remains absent for the Windows shell path, so runtime
trust must not be confused with coverage and the evidence gate remains closed.
