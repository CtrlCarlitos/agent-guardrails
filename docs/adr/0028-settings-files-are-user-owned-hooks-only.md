# ADR-0028: Settings files are user-owned; enforcement lives in the Engine

## Status

Accepted (operator, 2026-09-22). Supersedes [ADR-0022](./0022-degraded-mode-floor-fallback.md)
for claude, opencode and antigravity; ADR-0022's capability table survives as
the contract for what the opencode plugin does while its Engine is
unreachable. **Codex is a named exception and keeps its floor** (see
"Codex: the exception plane").

**Update, 2026-09-25 (#357): phases B and C shipped.** The Claude and OpenCode
generators no longer emit a floor, and `guardrail plane enable` removes the
floor an earlier release wrote: exactly the entries guardrail generated, now or
in a past release, with the operator's own entries and any value they edited
left alone. The removal runs only under an approval that names it, never on the
first-install bootstrap path, which can only tighten (ADR-0030). The generator
lists survive as frozen data in `internal/genconfig/legacy_floor.go`, used to
recognise old output and for ownership-drift detection, not to generate.

Implementation is phased and the phases retire independently; the plan and its
preconditions are recorded below rather than in a tracking issue, because the
order is the decision.

## Context

The operator built the first version of this project by writing rules into
each plane's settings file, then added a script that watched commands and wrote
more rules in. That was rejected as unmanageable. The recorded principle:

1. **Settings files belong to the user.** Actual settings are written by the
   user.
2. **The machinery is the guardrail** — the Engine and the hooks are the
   enforcement, and they are meant to be available at all times. The operator
   can disable the integration explicitly (plane lifecycle) when they want it
   off.
3. **Guardrail-owned writes to settings are the exception**, and must be
   minimal, small and stable.

The Declarative floor (ADR-0022) recreated the rejected shape at scale. Audited
across four seats (#278, #282):

| Plane | Hook / adapter | Floor entries | Drift |
|---|---|---|---|
| Claude | 3 hooks | 243 generated (223 deployed) | 24 behind |
| OpenCode | 1 plugin entry | 251 generated (218 deployed) | 8 behind, and those 8 are syntactically dead on the audited host |
| Codex | 3 hooks | 32, deployed byte-identical | **zero** |
| Antigravity | 2 hooks + `enabled` | **0** | zero by construction |

Three findings decided this ADR.

**The floor is a near-perfect mirror of the Engine.** Mapping every generated
entry to an Engine verdict: OpenCode's missing-rules list is *empty* — a 100%
mirror. Claude's is four families out of 243 entries (96% already covered), and
three of those four are not safety gaps but places where the Engine is
deliberately narrower than a prefix-matching glob. The floor is not carrying
policy the Engine lacks; it is carrying a second, drifting copy of policy the
Engine already has.

**Antigravity is a working existence proof.** It has run hook-only on Windows
since [ADR-0008](./0008-antigravity-no-declarative-floor.md) with a zero-entry
floor and `matcher: "*"`, so every tool call reaches the Engine. Over 27,000
evaluations in a single audited session, zero floor, zero drift, and a clean
removal path. The reset generalizes a model already in production rather than
proposing an untested one.

**The floor is the one guardrail-owned surface with no ownership marker.** Hook
groups carry `id: guardrail-<plane>-<event>` and are removed precisely.
Permission entries are bare strings sharing an array with the user's own, which
produced two live defects: `plane disable claude` never removes the floor at
all, and `plane disable opencode` deletes the entire `permission` block
including user entries. A footprint that cannot be cleanly removed is the
opposite of "minimal, small and stable" regardless of its size.

## Decision

**Settings files return to user-owned content plus guardrail hook registration
only. Policy lives in the Engine.**

Hook entries remain, tracked by a manifest so that what guardrail wrote is
exactly what `plane disable` removes. Floor generation is retired per plane on
the schedule below.

### Preconditions, in order

**P0 — Record the rulings.** Done (#282): M3 refined, M4 and C1 retired as
floor classes, M1 approved, the reset plan adopted.

**P1 — The Engine gains M1.** Recursive or forced deletion whose resolved
target is the current working directory, a parent of it that is still inside
the repository, or the repository root itself. Keyed on the **resolved target**,
not on the literal operands `.` and `..`, so `rm -rf "$PWD"` and
`rm -rf ../<repo-name>` are the same rule.

M1 is the only demonstrated safety gap in the entire four-seat audit, and it is
cross-confirmed: three of the four floors gate it independently, the fourth has
no floor at all, and two seats measured the Engine's permissiveness separately.
Deletion *outside* the repository already denies (`P1.rm-rf`); this is
specifically the working tree and its own root.

**P1 gates every retirement phase below.**

**P2 — The Engine gains M2.** `gh ssh-key add|delete` and
`gh gpg-key add|delete` ask. Today these allow, except when the key path
argument happens to be secret-tier and `P4.secret-path` denies it incidentally —
`gh ssh-key add /tmp/key.pub` allows. Durable account-level access must not
depend on the spelling of an argument.

### Retirement phases

| Phase | Plane | Retires | Gated on |
|---|---|---|---|
| A | **Antigravity** | nothing — already at target | — |
| B | **OpenCode** | all 218 deployed entries | P1 + recorded posture acceptance |
| C | **Claude** | all 243 generated entries | P1 + P2 + recorded posture acceptance |
| D | **Codex** | **nothing, indefinitely** | doctor-observed hook dispatch |

Planes retire independently. They are not one switch, and the four seats have
materially different readiness.

### Recorded posture acceptances

Retiring a floor changes what happens during an Engine outage. Both changes are
accepted deliberately, and are written here so that a later reader finds the
decision rather than infers it from an absence.

**OpenCode — mode-2 reads and edits become ungated.** The seat audit observed
three distinct modes: Engine alive (Engine governs, floor inert); Engine
unreachable with the plugin alive (bash fails closed regardless of the floor,
while reads and edits proceed *under the floor*); and the plugin itself missing
or broken (the floor is the only gate). Retiring the floor means that in the
second mode, reads and edits proceed **ungated** for the outage window. Bash is
unaffected — it fails closed there whatever the floor says, which is why all 94
bash entries are already inert in that mode. The third mode is the operator
explicitly disabling the integration, which principle 2 places in their hands.

**Claude — an outage is an unguarded window.** Claude Code silently no-ops a
failed hook spawn ([#151](https://github.com/CtrlCarlitos/agent-guardrails/issues/151)),
so when the Engine cannot be reached the call simply proceeds. There is no
adapter to fail closed. With the floor retired, Claude is ungated until the
Engine is restored. The operator accepts this consciously, in exchange for
settings files that are theirs and a policy that lives in one place.

This is the exposure that makes the loud-outage posture below a requirement
rather than a nicety.

### The loud-outage posture

Silent floor coverage is replaced by a visible state. An Engine that cannot be
reached must be **noticed**, not quietly compensated for:

- a `SessionStart` warning naming the outage, so the agent and the operator
  both learn about it at the start of the work rather than after it;
- a `doctor` probe reporting Engine reachability and, per plane, whether hook
  dispatch has actually been observed.

The trade this ADR makes is explicit: a floor that silently covered some calls
and drifted out of date is exchanged for no coverage and a loud signal. That is
only an improvement if the signal is real, which is why the posture ships in
the same phase as the retirements and not after them.

## Codex: the exception plane

**Codex keeps its native floor as primary enforcement. Generation continues for
Codex alone.**

Codex's pre-hooks do not dispatch on Windows
([openai/codex#24453](https://github.com/openai/codex/issues/24453)):
`guardrail doctor --codex-hooks` reports `runtime dispatch observed: no` and
`runtime coverage claim: none`. Its 32-rule native floor at
`~/.codex/rules/guardrail.rules` is deployed, byte-identical to `CodexRules()`,
and carries zero drift — the best-maintained floor of the four.

**This is a different thing from Claude's accepted exposure, and the
distinction is the reason for the exception.** Claude's #151 window is bounded:
the Engine is normally reached, and an outage is an event. Codex's
non-dispatch is not a window — it is the steady state on this platform.
Removing its floor would not accept a bounded exposure; it would leave a plane
with no enforcement at all, while the reset's story claims enforcement moved
into the Engine. For Codex, it has not moved, because nothing arrives.

Retirement is therefore gated on a **measurable condition, not a date**:
`doctor` reporting observed hook dispatch for Codex. When that flips, Codex
joins phase C's shape and its floor retires on the same terms as the others.

Two consequences follow, both deliberate:

- The M4 and C1 floor classes are retired from the **Claude and OpenCode**
  generators only. For those planes the Engine covers the real cases and the
  retired entries are prefix-matched no-ops. For Codex the floor *is* the gate,
  so removing a blanket rule there removes enforcement rather than a false
  positive. `CodexRules()` keeps them while the exception stands.
- Anyone reading this ADR as "the floor is gone" is reading it wrong. The floor
  is gone from three planes. On the fourth it is the only thing there is.

## Rejected alternatives

- **Shrink in place** (the #278 recommendation, superseded). Reducing OpenCode
  by 127 entries and holding Claude until #151 keeps the drift, keeps the
  ownership ambiguity, and keeps two copies of the same policy. It treats the
  symptom.
- **Retire the floor everywhere, including Codex.** Would leave a plane
  unmediated while claiming the opposite. Rejected on the evidence of the codex
  seat audit.
- **Keep the floor and fix the drift** (regenerate on every release, warn in
  doctor). Addresses drift but not ownership: the entries remain unmarked,
  unremovable, and a second source of truth that must be kept in step by
  machinery nobody wants to maintain.
- **Retire hooks too, and rely on the plane's own permissions.** Rejected
  immediately: the hooks are the machinery. Principle 2 is that the guardrail
  is the Engine plus the hooks, not the settings.

## Consequences

- Settings files become user-owned content plus a small, marked, precisely
  removable hook registration. The dotfiles' "forced entries" become hooks
  only.
- Policy has one home. A rule is added once, in the Engine, and every plane
  gets it — instead of once in the Engine and again in four renderings that
  drift apart at different rates.
- An Engine outage is loud and ungated on claude/opencode/antigravity, rather
  than quiet and partially covered. The exposure is named per plane above.
- **Codex's enforcement posture is unchanged by this ADR** and remains
  floor-primary until its upstream blocker is resolved.
- ADR-0022 is superseded for three planes. Its capability table remains live as
  the opencode plugin's contract for the Engine-unreachable mode, because that
  mode still exists — what changes is that the floor is no longer behind it.
- The two `plane disable` defects (claude leaves the floor behind, opencode
  deletes user entries) are resolved by the manifest, which must land with the
  retirement phases rather than after them.

## Amendment 1 — the ownership manifest (operator, 2026-09-22)

The decision above requires guardrail's entries to be precisely removable. This
amendment records the mechanism, because designing it surfaced a constraint the
original decision did not anticipate.

### Why a key list is not enough

Merging does not simply write guardrail's entries. Where both guardrail and the
operator name the same pattern, the **stricter verdict wins**, so guardrail
overwrites an operator value that was looser. "Guardrail wrote this" therefore
never implies "this did not exist before guardrail".

A manifest recording only ownership would make removal delete the key, and the
operator's own setting would be gone — the same harm the manifest exists to
prevent, reintroduced by the fix for it.

**So the record stores the prior value, and removal restores rather than
deletes.**

### The record is the diff

The manifest is the diff of the target document across a merge: what the file
gained, and what each changed key held before. One mechanism covers every
plane — a string in Claude's `permissions.deny[]`, a key in OpenCode's
`permission.bash{}`, a group in `hooks{}` — instead of a schema per config
shape.

That shape also gets a property worth naming: an entry guardrail generated but
did not actually change, because the operator already had it, produces no diff.
Guardrail does not claim it, and removal leaves it alone. Deriving ownership
from the generated fragment instead would claim entries guardrail never wrote.

The record **accumulates** across merges. Merging is idempotent and gets run
repeatedly; a second merge's diff is empty, and writing that would erase the
record of everything the first wrote. Where both describe the same slot the
*recorded* prior wins, because on a second merge the value guardrail sees as
prior is its own first write.

### Location and degradation

`$XDG_STATE_HOME/guardrail/manifests/<plane>.json` (`%LOCALAPPDATA%` on
Windows), following the coverage cache: this is guardrail's record of its own
actions, not operator-owned configuration. Another file the operator must keep
in step would be the problem, not the fix.

Every installation predating this amendment has no manifest, and state
directories get cleared, so absence is ordinary. Removal then falls back to
what an honest removal can conclude without a record: hooks by their
`guardrail-` id, the opencode plugin by its basename, and permission entries
by regenerating what the binary would write and removing only exact matches.
The fallback is narrower — it cannot restore a prior it never saw, nor
recognise output from an older release — and it reports that it was a fallback,
because a degraded removal must not look like a clean one.

### Operator edits are left alone

If an entry's current value no longer matches what guardrail wrote, removal
leaves it and reports it. The operator changed it since; it is theirs now, and
silently reverting an edit is the same class of harm as deleting one.

### Drift becomes visible

`doctor` reports three conditions per installed plane, each meaning something
different: entries **missing** from settings (the floor drifted), entries
**present but unclaimed** (output from an older release that nothing would
otherwise clean up), and entries the operator has **edited**. A plane with no
manifest says so rather than reporting clean, since absence of knowledge is not
absence of drift.

### Consequence for the retirement phases

Without the manifest, phase 1 does not remove the floor from anyone's settings
file — it only stops generating it, and the entries already on disk stay
forever. That is the first defect above applied to the reset itself, which is
why this is a precondition and not a follow-up.
