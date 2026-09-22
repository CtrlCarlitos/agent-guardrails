# Error-Message Discipline

Every denial and every error the guard produces is read by an AI agent
operating under pressure. The message is the only thing standing between
a stuck agent and a productive one. A wrong diagnosis costs more than a
missing one; a dead end manufactures the workaround it was meant to
prevent.

## The checklist

When writing or reviewing an error message, verify every item:

1. **Names the rule ID** — the agent and the operator need it to find the
   policy, file an issue, or check the runbook.

2. **States the diagnosis, not just the verdict** — "the pipe is owned by
   an impostor" tells the operator what to do; "access is denied" tells
   them nothing.

3. **Gives an actionable next step** — name the tool to use, the command
   to run, or the path to take. If no next step exists, say "involve the
   operator" — never leave a bare dead end.

4. **Is correct about what went wrong** — a squatted pipe reported as
   "already running" sent the operator away from the actual problem.
   If the diagnosis requires host knowledge the engine doesn't have,
   say "unverified" rather than guessing.

5. **Names the tool to reach for, when one exists** — "use the Write or
   Edit tool instead of a shell literal" is prescriptive; "use another
   method" is not.

6. **Does not mislead into out-of-band workarounds** — if a sanctioned
   path exists, the message must point to it. An unmediated workaround
   that the gate pushed the agent toward is strictly worse than the
   original denial.

## The enforcement

- `internal/adapter/guidance.go` — `denyNextStep` maps every rule ID to
  its prescriptive next step. `TestGuidanceDenyFallbackStillDirectsWork`
  pins the default against dead ends.
- `TestGuidanceDenyIsActionablePerRule` pins the per-rule next steps
  against the families in the table above.

## The failure modes this prevents

Each of these was observed live during the 2026-09-20 Windows bring-up:

- **Confidently wrong diagnosis** — the squatted pipe reported "approval
  daemon is already running" when an impostor held the name. The operator
  couldn't act because the message was about the wrong problem.
- **Misleading %PATH% error** — `executable file not found in %PATH%` for
  a file sitting right there, because the build output lacked the `.exe`
  suffix (#198).
- **Unsatisfiable approval demand** — "retry within 10 minutes" when no
  approval channel existed on the platform (#168). The documented
  workaround was to leave the guarded session.
- **Ask-fatigue** — if the ratio of asks answered-yes-without-reading
  climbs, the gate is decorative. Every unnecessary ask erodes the trust
  that makes the necessary ones effective.
