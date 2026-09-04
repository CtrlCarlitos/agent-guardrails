# Prompt-injection hygiene (P7's coding-practice half) is already satisfied

DESIGN.md's P7 names a set of coding practices for hook code itself: treat
all tool input/output/fetched content as untrusted data, parse with a real
JSON parser rather than `eval`, never build model-facing text by string
interpolation, validate paths with `readlink`/prefix-checks rather than trust.

Audit: `internal/adapter/claude.go` uses `encoding/json.Unmarshal`, never
shells out to interpret payload content. `internal/adapter/claude.go`'s
`EmitClaude` builds its JSON response via `encoding/json.Marshal` on a
`map[string]any`, never string concatenation — a malicious `Reason` string
cannot break out of the JSON structure. `internal/engine/rules_path.go`'s
`checkSymlinkEscape` resolves paths with `filepath.EvalSymlinks` and a
prefix check, not string matching. No hook code anywhere in this repo shells
out to `eval`, `sh -c` with unsanitized interpolated text, or similar.

Decision: no new code for this half of P7. Recorded here so the practice is
traceable to a decision, and so a future contributor doesn't wonder why P7
has no corresponding "hygiene" module — [`0006`](./0006-two-signal-trifecta-heuristic.md) covers the other half.
