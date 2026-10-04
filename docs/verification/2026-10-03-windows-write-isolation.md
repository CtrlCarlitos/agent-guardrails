# Windows write failure: fixture ACL root cause

Native Codex CLI 0.160.0 was compared using a deterministic local Responses
provider, disposable git workspaces and isolated CODEX_HOME/config/state.
No model service, production configuration or sandbox credential contents
were involved. Every case retained workspace-write sandboxing and selected
the documented unelevated Windows implementation.

| Case | Flat patch | Nested patch | Requested shell cwd | Hooks |
| --- | --- | --- | --- | --- |
| Control | Failed to write | Failed to create parent directories | Actual PowerShell installation directory | None configured or logged |
| Guardrail | Failed to write after pre-hook | Failed to create parent directories after pre-hook | Guardrail rejected execution-directory mismatch | Fixture hooks dispatched |
| Explicit Codex process cwd | Failed to write | Failed to create parent directories | Still PowerShell installation directory | None |
| Explicit cwd and legacy desktop | Failed to write | Failed to create parent directories | Still PowerShell installation directory | None |

The control's actual shell location was `C:\Program Files\PowerShell\7`
despite an absolute workspace in both `codex exec -C` and the tool's workdir.
Passing cwd directly to subprocess creation did not correct it. Setting the
documented `windows.sandbox_private_desktop = false` only in the fourth
disposable fixture also did not correct it.

Reports, beneath test/smoke/.test-tmp/windows-write-comparison:

- `without-hooks-u6f9yx3o`
- `with-hooks-isqjfpiq`
- `without-hooks-19t3eodh`
- `without-hooks-tm8lqb9v`

Codex itself exited 0 after each deterministic conversation, but the actual
patch outputs exited 1 and both target files remained absent. Conversation
completion is not successful tool execution. The diagnostic observer's
exit status likewise does not claim acceptance; inspect its file and tool
outputs. Issue #349's acceptance probe still requires actual file effects
and post-hooks, and remains non-green on Windows.

## Reproduction

From an ordinary operator terminal, with a built fixture binary:

```powershell
python -B test/smoke/windows_write_diagnostic.py ./probe-build.exe
python -B test/smoke/windows_write_diagnostic.py ./probe-build.exe --process-cwd --without-hooks-only
python -B test/smoke/windows_write_diagnostic.py ./probe-build.exe --process-cwd --without-hooks-only --legacy-desktop
```

Each run writes raw provider requests, Codex stdout/stderr and report JSON.
The no-hook cases deliberately do not configure fixture hooks; production
hooks are neither edited nor disabled. The comparison uses no dangerous
file action: it attempts two ordinary text-file additions and Get-Location.

## Root cause and measured repair

The apparent runtime blocker was caused by temporary fixture creation.
Installed Python 3.14's `tempfile.mkdtemp` calls `os.mkdir(path, 0o700)`.
On this Windows host the resulting root replaced the inherited explicit
current-user ACE with OWNER RIGHTS. Codex's restricted-token execution could
not write beneath that root, and shell location initialization fell back to
the PowerShell installation directory.

Adding an explicit inheritable current-user ACE only to the existing
`direct-backend-vltpl7k6` root made the identical direct sandbox command exit
0 and write `direct-write\n`; the initial run had exited 1 with Access Denied.
No credentials, production settings, Everyone permission or sandbox policy
were changed. This intervention identifies the fixture ACL as a cause, rather
than merely showing that the failure also occurs without hooks.

`create_probe_directory` now allocates Windows fixture roots atomically with
ordinary mkdir and a cryptographically random suffix. They inherit the
checkout's ACL instead of applying Windows mkdir's special 0700 ACL. POSIX
continues to use owner-only tempfile creation. Private operator/action-store
directories retain their separate privatefs protections.

The native owner-access regression failed with tempfile creation and passed
with inherited creation; all 24 Python probe tests passed. Repeating the
original comparison then succeeded for flat and nested patches, with the
correct shell location, both without hooks and with hooks:

- `without-hooks-f09b9bf5c836a4704dc9dae6e4dcc5da`
- `with-hooks-51a71ca0589c752ab5faef128576285b`

The hosted Windows checkout did not contain the test's assumed explicit
owner ACE. The regression now seeds that precondition in its own disposable
parent using a DACL-only current-user grant. Its child-access assertion is
unchanged: substituting the old allocator still fails that assertion, while
all 25 tests pass with the fixed allocator. No hosted checkout permissions,
sandbox policy, protected credentials or CI workflow were changed.

## Correction to the initial inference

The initial failures reproduced without Guardrail, but that did not establish
an upstream Codex defect. The fixture's inaccessible root affected both
cases. The explicit-owner intervention and successful inherited-root reruns
correct that inference.
Do not weaken Guardrail's execution-directory check or count the terminal
approval ceremony as full Windows acceptance.

No machine-wide sandbox repair is justified by these results. The older openai/codex#24453 is
about missing hook dispatch; it is not evidence for this separate write/cwd
failure, since hooks dispatched in the measured fixture.

Official reference: [Windows sandbox](https://developers.openai.com/codex/windows/).
It documents the preferred elevated and fallback unelevated modes, desktop
compatibility setting, and sandbox setup/permissions diagnostics. It also
explicitly excludes sandbox credential contents from diagnostic sharing.
