# GitHub `main` protection

**Status:** agreed with Carlitos 2026-09-15.

## Why

`CtrlCarlitos/agent-guardrails` has no branch protection or rulesets. Anyone
with write access can directly modify, force-push, or delete `main`, and CI or
review is not enforced before a merge. Secret scanning remains useful but does
not establish a protected merge path.

## Decision

Create one active GitHub repository ruleset targeting only `main`. It creates
the normal merge path below while retaining an explicit repository-administrator
bypass for documented emergencies and solo-maintainer changes.

### Pull request gate

- Require a pull request before merging.
- Require one approval from someone other than the most recent pusher.
- Dismiss stale approvals when new commits are pushed.
- Require all review conversations to be resolved.
- Do not require Code Owner review; the repository has no `CODEOWNERS` policy.

### Required checks

Require successful completion of the current pull-request CI jobs:

- `test (ubuntu-latest)`
- `test (windows-latest)`

The tag-only Release workflow is not a required check because it does not run
on pull requests and would block every merge.

### History and integrity

- Require verified signed commits on `main`.
- Require linear history. Squash and rebase merges remain usable; merge commits
  are rejected.
- Block force pushes and branch deletion.

### Bypass

Repository administrators may bypass the ruleset. This is not a routine merge
path: it is reserved for a documented emergency or a solo-maintainer change
where independent approval cannot be obtained. GitHub's ruleset audit trail is
the record of each bypass.

## Scope

The ruleset applies only to `main`. Feature branches, tags, Releases, and the
repository's existing merge-method settings are not changed. This work does not
introduce a `CODEOWNERS` policy, required deployments, or an automated merge
queue.

## Verification

After creation, verify the active ruleset through the GitHub API and confirm it
targets `main`, has the two exact required checks, enforces pull-request review,
signed commits, and linear history, blocks deletion and force pushes, and lists
the administrator bypass actor. No test PR or bypass is created.
