# ADR-0034: One dual-major plugin serves OpenCode 1 and OpenCode 2; emission is selected by the detected major

## Status

Accepted (operator arming comment on #534, 2026-11-13). The dotfiles fleet
stays on OpenCode 1.19.x until a release of this port exists
(CtrlCarlitos/dotfiles#395, Model A: per-machine major choice), so V1
behavior must keep working unchanged — this ADR's decisions are all
conditioned on that constraint.

## Context

OpenCode 2 (v2.x, installed by `https://opencode.ai/v2/install`) replaces
the V1 binary in place and shares V1's config locations. Two of its
intentional breaking changes land on this plane, and either one alone
silently removes enforcement on an upgraded machine:

1. **V1 plugin implementations do not run in V2.** `tool.execute.before`
   becomes `ctx.tool.hook("execute.before", …)` on a context of domains,
   registered from a `setup(ctx)` function on a default-exported definition
   object (`{id, setup}`), not a returned hook map.
2. **V2 skips configured single-file plugin paths** with a warning: local
   plugin entries must name directories.

A third difference widens access rather than removing enforcement: V1 asked
before touching paths outside the project; **V2 allows `external_directory`
by default**. Porting the plugin without closing that default would
silently loosen the plane.

Facts verified live and against source (`anomalyco/opencode`, plugin
package dist types, a scratch v2.3.0 install; recorded on #534):

- `ctx.tool.hook("execute.before", event)` receives
  `{tool, sessionID, agent, messageID, id (the callID), input (the args)}`,
  and **throwing still blocks** (upstream's own migration example blocks
  `.env` reads by throwing; core: "Only tool execute.before may fail").
- V2 renamed tools: `bash`→`shell`, `apply_patch`→`patch`, `task`→`subagent`;
  read/edit/write/patch take `path` where V1 took `filePath`; `lsp` is gone.
- One file can serve both majors: V1 (≥ 1.18.29; the fleet is 1.19.x) calls
  `server()` / discovers the named export; V2 reads `default.id` and calls
  `default.setup()`. Superpowers ≥ 6.4.1 ships exactly this shape and runs
  on this machine's 1.19.5.
- V1 hosts ≥ 1.18.18 have been observed to invoke `default.setup()` with a
  V1-shaped ctx, so `setup` must feature-detect and return quietly.
- ADR-0015's model ports: V2 events `permission.asked` (carrying the tool
  callID in `source.id`) and `permission.replied` `{sessionID, requestID,
  reply}` replace V1's `permission.updated`/`permission.replied` shapes.

## Decision

**1. The shipped plugin is one dual-major file.** The named export
`GuardrailPlugin` (and `default.server`) serves V1 exactly as before; the
new `setup(ctx)` registers `ctx.tool.hook("execute.before", …)` for V2 and
returns quietly when invoked with a V1-shaped ctx. The plugin imports only
`node:*` builtins, so the `@opencode-ai/plugin` → `@opencode/plugin`
package rename does not touch it.

**2. The wire format does not change (ADR-0007 decision 1 stands).** The V2
hook normalizes its event into the same
`{session_id, event, tool, command, paths, cwd}` envelope, translating V2's
native names (`shell`→`bash`, `patch`→`apply_patch`, `subagent`→`task`) and
arg spellings (`path`) onto the V1-native names the engine contract and the
Go adapter already know. The Go side does not change.

**3. Emission is selected by the detected major.** `plane enable opencode`,
`setup`, `gen-config` and `sync` read `opencode --version` (V1 prints
`1.19.5`; V2 prints `opencode v2.3.0`) and emit:

| | V1 (or undetectable) | V2 |
|---|---|---|
| Artifact | `<state>/guardrail.js` (single file) | `<state>/guardrail/index.js` (directory) |
| Config entry | `plugin: [<file>]` | `plugins: [<dir>]` |
| Permissions | nothing (ADR-0028: no floor) | `permissions: [{action: "external_directory", resource: "*", effect: "ask"}]` |

An undetectable major keeps the V1 shape (unchanged behavior) and says so
loudly, because a wrong guess means no enforcement (V2 skips the entry).
`plane status`/`doctor` name the detected major and the installed entry
shape; a cross-major wiring reads as NOT registered with the remedy and
counts as a doctor problem. A machine that flipped majors converges on the
next `plane enable`/`setup`: the merge absorbs guardrail's own entries from
both keys while operator entries survive untouched (ADR-0028 amendment 1
discipline).

**4. `external_directory: ask` is a host-default restoration, not a floor
resurrection.** ADR-0028 retired mirroring Engine policy into settings
files; that stands. This one entry restores the pre-V2 *host* default V1
already had (ask before paths outside the project), closing a silent
widening V2 introduced. It is emitted only when the operator's config has
no rule for that action — their permissions array is theirs.

**5. Configured directory entry, not `~/.config/opencode/plugins/`
discovery.** V2 can discover plugins dropped into the global plugins
directory, which would avoid a config write for the plugin itself — but the
`permissions` entry must be written anyway, discovery-created files have no
ownership manifest (ADR-0028's precise-removal machinery covers config
entries, not arbitrary directories), and `plane disable` would need a
second removal mechanism. One manifest mechanism covering both majors'
entries is simpler and keeps removal honest. Operators may still move to
discovery manually; doctor does not depend on the difference.

## Rejected alternatives

- **Two plugin files, picked by major.** Two artifacts to keep in step for
  a transition window whose length the dotfiles' Model A does not bound;
  the single file is upstream's own documented pattern and Superpowers'
  proven one.
- **Rely on V2's in-memory normalization of V1 config.** "Supported V1
  syntax remains quiet" covers `plugin`→`plugins` key normalization, but a
  single-file path is *skipped*, not normalized, and the external_directory
  default is not affected by normalization at all.
- **Emit the full V1 floor lowered into `permissions` on V2.** Recreates
  the exact drift-and-ownership shape ADR-0028 retired, against its
  recorded findings.
- **Teach the engine V2 tool names as a second naming scheme.** Doubles the
  contract surface and the audit vocabulary for names that describe the
  same tools; translation at the adapter boundary is ADR-0007's design.

## Consequences

- A V2 machine guarded by a pre-port release is silently unguarded (both
  breaks); after this port, `guardrail setup` on that machine converges it
  to V2 wiring under one approval.
- The V2 server plugin context has no toast API (desktop-GUI plugins own
  toasts), so night-mode and pending-approval notices on V2 go to stderr —
  the same path a V1 host without a toast API already takes. Deny and ask
  guidance always travels in the thrown error the model sees.
- ADR-0011 (retry inference) remains the ask fallback on both majors;
  ADR-0015's host-owned approval correlation runs on each major's event
  shapes (V2: `permission.asked`/`permission.replied` via
  `source.id`/`requestID`).
- The V2 artifact is a directory with `index.js`; V2 loads that layout from
  a configured path without a `package.json`.
- `guardrail selftest`'s opencode probes drive `guardrail hook opencode`
  directly with the envelope, so they are major-agnostic and unchanged.
