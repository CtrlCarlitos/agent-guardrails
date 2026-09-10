# The Engine's shell semantics are complete; new shapes need a friction threshold

The Engine is a static analyser of tool calls. It reads a shell command, models
what the shell will do, and issues a Verdict before anything runs. Every command
shape it "understands" — a wrapper it unwraps, a variable it substitutes, an
operand it classifies — is code, and the space of shapes is unbounded. Between
2026-09-04 and 2026-09-07 the remediation added roughly 8,000 lines of Engine
code, most of it teaching the analyser new shapes. Each addition was justified
by a real false positive; together they were a treadmill.

The audit log shows the treadmill has done its job. After `v0.14.0-dev`, the
three planes produced about two prompts per three hundred tool calls, and both
of those prompts were correct. The remaining prompts are of two kinds: a small
number of frequent shapes worth one more pass, and a long tail of one-off
commands whose targets genuinely cannot be known without executing them.

Decision: after the shapes named in the 2026-09-07 audit pass (NF-17, NF-18,
NF-19) land, **the Engine's shell semantics are declared complete**. A new
false-positive shape is not an Engine change by default. It is routed to one of
three non-code answers, in this order:

1. **Agent hygiene.** Quote variables, use literal paths, avoid `$(…)` in a
   path position. The Ask reason must say what to change (e.g. "quote `$S`"),
   so the model corrects the command instead of asking the operator.
2. **The Overlay.** A project-specific pattern is a `[[rules]]` entry in that
   repository's `guardrail.toml`, or an Operator config grant — never a Base
   rule and never a parser case.
3. **The Ask.** A fail-closed prompt on a target the analyser cannot see is the
   design working. It is accepted as the price of not executing the command to
   find out.

An Engine change for a new shape is considered only when the audit log shows
that shape producing **at least ten non-allow Verdicts per day, across at least
two sessions**, for shapes an honest agent has no cheaper way to avoid. One
reporter is not a threshold. The change must model the *minimum* semantics for
that shape and fail closed at every boundary it does not model — no simulation
of shell modes, environments, or startup behaviour, and no callback
classification.

## Considered alternatives

- Keep adding shapes as they are reported. Rejected: the marginal shape costs
  more code than the last, the code has already twice grown a POSIX/environment
  simulator that a reviewer had to remove, and every parser branch is a place a
  bypass can hide.
- Replace the analyser with a linter such as ShellCheck. Rejected: a linter
  knows a command is badly written, not whether it is dangerous on this
  machine. It has no model of secret paths, safe roots, repository boundaries,
  resolved symlinks, or the working directory after a `cd`, and it offers no
  library interface.
- Execute the command in a sandbox to learn its targets. Rejected: outside the
  static boundary this project chose in ADR-0001 and ADR-0010; it would change
  what the guard is.

## Consequences

- NF-17, NF-18, and NF-19 landed by `v0.17.0-dev`, completing the final planned
  Engine work for shell semantics. H-6, H-10, NF-3, NF-11, NF-12, and candidate
  ADR-0013 containment are parked by the operator; later work begins only when
  explicitly scheduled.
- The audit log is the only admissible evidence for a new shape. The threshold
  is measured, not argued.
- Prompts that remain after this point are documented in the residual-risk
  section of the current plan, and agents are told how to avoid them.
- This decision can be revisited when a plane changes its tool-call boundary in
  a way that exposes new information to the Engine (for example, a native
  permission primitive on OpenCode).
