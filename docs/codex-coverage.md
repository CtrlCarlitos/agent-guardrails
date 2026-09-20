# Codex schema coverage

Run `guardrail doctor --coverage codex --schema /path/to/tools.json` to compare
an actual Responses tool declaration against the shared plane contract and MCP
registry. The input is either a JSON tools array or a request object containing
that array. This command reads a file; it does not start Codex or send a model
request. No approval or enforcement policy changes are made.

The deterministic `test/smoke/codex_probe.py` harness preserves `tools.json` in
its reported `artifacts` directory. Run it with a built Guardrail binary:

```sh
python3 test/smoke/codex_probe.py /absolute/path/to/guardrail
# Use the artifacts directory printed by the probe:
guardrail doctor --coverage codex --schema /path/from/report/tools.json
```

On Windows, invoke the same script with the active Python interpreter and an
`.exe` Guardrail build; the harness itself selects `sys.executable`, emits a
`.cmd` logger, and escapes Windows paths in disposable TOML:

```powershell
python test/smoke/codex_probe.py "$env:TEMP\guardrail-codex.exe" --mediation
```

Keep the probe's `report.json` alongside the schema to identify the CLI version
and execution mode. The doctor output includes the schema's SHA-256 digest.
This is coverage of the supplied configuration, not an inventory of all
possible runtime features, providers, or MCP servers. Code-mode exec/wait
schemas do not enumerate inner tools. Recollect schemas after runtime or
configuration changes. The installed CLI currently has no complete tool-schema
export command; automatic installed-runtime discovery is not provided here.

On Windows, the Codex plane is **registered, unenforced**: the generated hooks
can be present and trusted while `command_execution` still does not dispatch
`PreToolUse`. This is tracked upstream as
[`openai/codex#24453`](https://github.com/openai/codex/issues/24453). Until that
blocker is resolved and runtime dispatch is observed, doctor exits 1 on Windows
and its rows are contract inventory only—never a runtime coverage claim.

| Classification | Meaning |
| --- | --- |
| `contracted` | The projected hook name has a native contract entry. Deny and delegation entries are still reported as contracted. |
| `mcp-registry` | The shared registry types this MCP tool; path checks still depend on actual call arguments. |
| `mcp-prefix-deny` | An unregistered MCP tool falls under Codex's explicit prefix deny. |
| `uncontracted` | No matching native entry. Codex fails closed **if the call reaches Guardrail**. |
| `hosted-no-local-hook` | A provider tool declaration does not establish a local pre-hook checkpoint. |
| `unsupported-schema` | An unfamiliar tool kind needs investigation; it is not counted as covered. |

Exit 0 means every supplied tool has a native contract or MCP classification.
It does not mean hooks fired or that every runtime tool was supplied. Exit 1
means an uncontracted, hosted, or unsupported declaration was found, or that
Windows runtime enforcement remains unobserved. Exit 2
means invalid arguments, unreadable input, or an incomplete/malformed inventory.
Empty inventories, duplicate names, nested namespaces, invalid identifiers and
inputs larger than 8 MiB are rejected.

Contract entries absent from the input are **unobserved**, not proven retired.
`web.run` is further classified from each call's arguments by the adapter.
`write_stdin` remains denied under ADR-0014, and delegation remains denied.
Observed enforcement belongs to `selftest`; schema coverage cannot replace it.

Hook-name projections follow upstream `openai/codex` at
`7498521d288b9b3b96ffba4eedf089d8d6e06a84`: `HookToolName` in
`codex-rs/core/src/tools/hook_names.rs`, `function_hook_tool_name` in
`registry.rs`, `flat_tool_name` in `mod.rs`, and MCP `join_tool_name` in
`handlers/mcp.rs`. These are diagnostic projections only and do not extend
Guardrail's enforcement aliases. Unknown namespace spellings remain findings.
