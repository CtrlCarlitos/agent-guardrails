# Marker-based owned hook entries in generated plane config

`guardrail gen-config <plane> --merge <settings>` runs unattended from the dotfiles
installer on every `chezmoi apply`, and the `--binary` path it registers can change
(a version bump moves the install path, or a user hand-edits). The Plan 2 merge
union-appended hook entries keyed by their exact JSON. Empirically that *forks* the
hook: a changed `--binary` adds a second entry, so the engine is invoked twice per
tool call and the stale path errors on every call, forever.

Decision: guardrail-owned hook groups carry a stable marker — a string `id` field
with the prefix `guardrail-` (`guardrail-claude-pre`, `guardrail-claude-post`). The
`hooks` merge path is special-cased: for each event, dst groups whose `id` has that
prefix are dropped and replaced wholesale by the generated groups; dst groups
without the marker are user data and are union-appended against, never mutated.

`permissions.deny` / `permissions.ask` stay union-append — permission entries are
bare strings with nowhere to hang a marker, and a stale *deny* is fail-safe. A
`guardrail sync --prune` (Plan 7) is the eventual cleanup for drifted permission
lists.

## Consequences

- Claude Code ignores unknown keys in a hook group, so the `id` is inert to it.
- Re-running `--merge` with a different `--binary` converges to exactly one owned
  group per event.
- If a user copies a guardrail group and edits it without removing the `id`, the
  next merge will replace their copy. Documented; the `id` prefix is reserved.
