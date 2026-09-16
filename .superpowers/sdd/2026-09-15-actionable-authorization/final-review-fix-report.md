# Final Review Fix Report

## Scope

Addressed all final-review findings for actionable authorization.

## Root Cause

Ask guidance was bounded twice. `guidanceForModel` truncated the encoded native
action to fit a model-facing cap, then each Adapter applied generic final
sanitization that could again truncate the composed guidance. A large policy
reason could therefore push the mandatory exact-action and retry constraints
out of the final protocol payload.

## Changes

- Bound and single-line-sanitize only the Ask policy reason before rendering the
  guidance. The safely JSON-encoded native action is never truncated.
- Centralized final model-facing sanitization in `guidanceForModel` for non-Ask
  verdicts, and removed per-Adapter final sanitization so an Ask cannot be
  truncated after its mandatory text is composed.
- Added OpenCode Adapter regressions proving a long action remains complete and
  an oversized reason still retains the exact action and both retry constraints.
- Replaced both ADR prose references with Markdown links resolving from
  `docs/adr/` to the approved design specification.

## Test Evidence

The two new regressions were run before the production change and failed for the
reported reasons: the long action was truncated, and the oversized reason
omitted the mandatory Ask content. They passed after the implementation change.

Completed verification:

```text
go test ./internal/adapter                         PASS
go test ./internal/genconfig                       PASS
go test ./cmd/guardrail -run 'Hook|hook'           PASS
go test ./...                                     PASS
```

Final pre-commit verification also passed:

```text
make check       PASS
git diff --check PASS
```
