# Contract fixtures

Recorded real hook payloads per plane (claude/, opencode/, antigravity/) paired
with the expected verdict and the expected native response. The bulk of CI.

Codex fixtures use its native hook envelope, with canonical `Bash` and
`apply_patch` inputs under `tool_input.command`. The contract runner substitutes
a real temporary cwd for `/repo` so the allowed-command directory precondition
can be emitted. `model-catalog.json` and `mcp_server.py` belong to the native
smoke probe; they are not fabricated hook-coverage evidence. `hooks.golden.json`
records the generated configuration, and `expected.json` lists only executable
hook contract cases.
