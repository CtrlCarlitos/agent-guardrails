# Codex schema fixtures

`codex-direct.json` preserves the tool types, names and namespace structure
from the Codex CLI 0.154.0 deterministic Responses probe captured during the
2026-09-18 coverage audit. Descriptions and schema bodies are omitted because
the extractor does not inspect them; parameter/format objects retain their
structural role. The MCP server is the local fixture, not a user's server.

`codex-code-mode.json` is a minimal fixture for the exec/wait outer surface.
It intentionally cannot prove anything about inner tool coverage.
