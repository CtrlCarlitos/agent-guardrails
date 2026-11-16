# Repository-authorized delivery

`/deliver` or an applicable "fix on red, merge on green, clean up on merged"
instruction supplies the task's delivery endpoint. Guardrail's repository
authorization supplies the enforceable permission. Enable it once on this
machine for the physical repository; linked worktrees and planes share that
authorization. Windows and WSL have separate operator configurations.

## Operator setup

Review GitHub's repository settings first: one enabled merge method, active
nonempty required checks bound to their integration, strict/up-to-date checks,
no bypass for this credential, and delete-branch-on-merge enabled. This first
version supports branch rulesets, not classic-protection-only repositories or
merge queues. Additional GitHub review requirements continue to apply.

From the primary checkout in your own terminal:

```sh
guardrail delivery enable --github CtrlCarlitos/agent-guardrails --base main --method squash --protect 'ci/**' --protect 'scripts/ci/**'
guardrail delivery status
```

Choose protected globs for the actual scripts/configuration that define CI in
this repository; the example paths are not an automatically inferred dependency
closure. Workflows, local Actions, CODEOWNERS and `guardrail.toml` are protected
by default. CI-control changes require the operator's normal merge path.

The terminal shows the complete policy and asks once, using the existing
prompt/passkey mode. Authorization pins GitHub's numeric repository ID, name,
default branch, method and additional protected paths in machine-owned Operator
config. An agent, Overlay or skill cannot enable it. No credential or service is
installed. This deliberately retains the existing account/Guardrail trust model;
it does not claim to remove the account's administrator capabilities or prove the
semantic completeness of its test suite.

Authorization lasts until the operator revokes it:

```sh
guardrail delivery revoke
```

Revocation or a policy change stops the next mutation. Existing per-command
grants and default Ask/Deny behavior remain unchanged for other operations.

## Agent workflow

Implement, run the repository's local verification, open the PR, fix real CI
failures and wait for the required checks and reviews. Preserve the task's
authorization, branch/worktree, PR and exact tested head when resuming.
"Design only" and "stop at the PR" remain narrower endpoints.

Once green, from the primary checkout outside the task worktree:

```sh
guardrail delivery finish --pr 123 --head 0123456789abcdef0123456789abcdef01234567 --worktree /absolute/path/to/task-worktree
```

Use the actual PR, full head SHA and registered linked-worktree path. Omit
`--worktree` for a task without a linked worktree. The executor rechecks the
operator policy, repository identity, active rules, credential bypass posture,
complete protected-path diff and successful required checks. It rejects pending,
cancelled, skipped, neutral, missing and wrong-integration results. APIs have
bounded responses/timeouts; an API failure never uses a cached previous allow.

It sends a head-pinned immediate merge request. GitHub enforces the remaining
branch/review requirements at execution; no administrator bypass is requested.
It confirms the merged PR and merge SHA before cleanup. An uncertain response
preserves resources; retrying checks the actual PR state instead of blindly
merging again. The agent's local-verification obligation still applies; the
executor verifies GitHub's required checks, not a claim about local test output.

## Cleanup and completion

GitHub's delete-on-merge owns remote branch deletion. The executor verifies the
remote task ref is absent; it does not perform a blind remote DELETE that could
discard a newer push. A remaining remote ref is a concrete cleanup blocker.

Local cleanup is limited to the PR's exact branch tip and optional registered
task worktree. It requires ancestry in the current default branch, or for a
squash, the complete head tree exactly equal to the recorded, reachable squash
tree. The latter preserves final tracked content in history, **not** the original
commit messages, signatures or intermediate states. No patch-id heuristic is
used; squash merges with differing trees require operator review.

Modified, untracked and ignored files, sparse/assume-unchanged index flags,
submodules, locked/other worktrees and symbolic refs stop cleanup. It uses
non-force worktree removal and an expected-old-OID ref deletion. A cleanup lock
serializes this executor's concurrent calls; state is checked again after
authorization/audit. Keep the task's worktree quiescent during removal: this is
not filesystem isolation against an unrelated process deliberately racing writes.

Audit success is required before a mutation. A confirmed merge with failed
cleanup reports `merged / cleanup blocked`; preserve the resources and resume
that cleanup after resolving the exact condition. A successful run reports
`delivery complete`. It does not authorize arbitrary `gh pr merge`, branch
force deletion or worktree removal commands outside this executor.

The legacy installed binary must be upgraded before using these commands.
Changing the skill alone cannot enable Guardrail delivery or override a denial.
