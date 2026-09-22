# ADR-0026: Built-In and Overlay Verdicts Combine by Severity

## Status

Accepted

## Context

The engine evaluates a tool call against three layers: the path policy, the
built-in command analyzers (P1/P5/P6 families and their kin, hardcoded in the
engine), and the Overlay's custom rules (`guardrail.toml`). Until #235 added
the credentialed-CLI family, no built-in rule and no common Overlay rule ever
matched the same command, so the question of precedence never arose. When
`P6.cloud-mutate` began firing on `terraform apply`, the waiver test fixture
silently started measuring the built-in instead of the Overlay rule it
existed to test (claude caught this during #264; the fixture moved).

The underlying behaviour was never deliberately chosen. When a built-in rule
and an Overlay rule match the same command, three postures are possible:
built-in wins outright, Overlay wins outright, or the more restrictive
Verdict wins. Choosing matters because a project that legitimately allows a
command in its Overlay (a deploy repo allowing `terraform apply`) would be
silently overridden by a built-in it did not write, and a project that
tightens a built-in would be silently ignored.

## Decision

1. Verdicts from all layers combine by severity: deny > ask > allow. The
   most restrictive Verdict wins regardless of which layer produced it.
2. An Overlay may tighten a built-in (its deny overrides a built-in ask) but
   never loosen one (an Overlay allow cannot clear a built-in ask). This is
   the existing policy invariant - the Overlay tightens, never loosens -
   extended to built-in rules.
3. At equal severity, the built-in's rule ID reports. `Evaluate` keeps the
   first hit and the built-in analyzers precede `matchOverlayRules` in the
   hit list. Operators diagnosing a deny see the engine's rule family first;
   the audit log records the full hit set.
4. Waivers apply to both layers by rule ID. An operator-authorized waiver on
   a built-in rule ID (`P6.cloud-mutate`) clears that built-in, after which
   the surviving layer's posture governs - including an Overlay allow. This
   is the escape valve: a project that legitimately needs to relax a
   built-in for a command the built-in mishandles does so through the
   existing waiver machinery, never silently.
5. The four-case collision matrix is pinned in
   `TestBuiltInAndOverlayVerdictsCombineBySeverity`:
   overlay-cannot-loosen, overlay-can-tighten, equal-severity-reports-the-
   built-in, and waived-built-in-falls-through.

## Consequences

- No engine change was required; this ADR records and pins the behaviour
  the engine already exhibited once built-ins and Overlays began to
  overlap.
- Every future built-in family that overlaps a plausible Overlay pattern
  inherits this combination rule without new machinery.
- A project cannot relax a built-in without an operator-authorized waiver.
  The waiver request flows through the existing Operator-config grant, so
  the loosening is never silent.
- The audit log records which layer produced the winning Verdict; the
  losing layer's hit remains visible for diagnosis.
- The fixture comment in `fullPol` (evaluate_test.go) documents the original
  collision; the waiver test now uses a command no built-in covers, and the
  collision matrix has its own dedicated test.
