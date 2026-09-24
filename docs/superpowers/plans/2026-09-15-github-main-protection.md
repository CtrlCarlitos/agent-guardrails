# GitHub Main Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the approved GitHub merge, integrity, and recovery controls on `CtrlCarlitos/agent-guardrails` `main`.

**Architecture:** Create one active repository ruleset targeting only `refs/heads/main`. The GitHub API is the source of truth: create the ruleset once, then read it back and query effective branch rules to prove the intended controls are active.

**Tech Stack:** GitHub REST API through GitHub CLI, API version `2022-11-28`.

**Spec:** `docs/superpowers/specs/2026-09-15-github-main-protection-design.md`

## Global Constraints

- Target only `refs/heads/main`; do not change tags, feature branches, Releases, or merge-method settings.
- Require exactly `test (ubuntu-latest)` and `test (windows-latest)`, both locked to GitHub Actions App ID `15368`.
- Require one independent approval, dismiss stale approvals, require resolved conversations, and do not require Code Owner review.
- Require signed commits and linear history; block deletion and non-fast-forward updates.
- Repository administrators bypass with `RepositoryRole` ID `5` and mode `always`.
- Do not add an up-to-date-before-merge requirement or a merge queue.

---

### Task 1: Create And Verify The Active `main` Ruleset

**Files:**
- Modify: GitHub repository rulesets for `CtrlCarlitos/agent-guardrails`.
- Test: GitHub REST read-back responses for the created ruleset and `main` effective rules.

**Interfaces:**
- Consumes: authenticated `gh` session with repository-admin access.
- Produces: one active ruleset named `Protect main` and its returned GitHub ruleset ID.

- [ ] **Step 1: Confirm the precondition without modifying GitHub**

Run:

```sh
gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  repos/CtrlCarlitos/agent-guardrails/rulesets
```

Expected: an empty JSON array. If a ruleset already targets `main`, stop rather
than creating a duplicate and compare it with this plan.

- [ ] **Step 2: Create the ruleset using the approved payload**

Run:

```sh
gh api --method POST \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  repos/CtrlCarlitos/agent-guardrails/rulesets \
  --input - <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}],
  "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
  "rules": [
    {"type": "pull_request", "parameters": {"dismiss_stale_reviews_on_push": true, "require_code_owner_review": false, "require_last_push_approval": true, "required_approving_review_count": 1, "required_review_thread_resolution": true}},
    {"type": "required_status_checks", "parameters": {"do_not_enforce_on_create": false, "strict_required_status_checks_policy": false, "required_status_checks": [{"context": "test (ubuntu-latest)", "integration_id": 15368}, {"context": "test (windows-latest)", "integration_id": 15368}]}},
    {"type": "required_signatures"},
    {"type": "required_linear_history"},
    {"type": "deletion"},
    {"type": "non_fast_forward"}
  ]
}
JSON
```

Expected: HTTP success response containing an integer `id`; record it as
`RULESET_ID` for the remaining steps.

- [ ] **Step 3: Verify the stored ruleset equals the approved contract**

Run:

```sh
gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "repos/CtrlCarlitos/agent-guardrails/rulesets/$RULESET_ID" \
  --jq '{id, name, target, enforcement, conditions, bypass_actors, rules}'
```

Expected: `Protect main`, `active`, `refs/heads/main`, the administrator
`RepositoryRole` bypass, and precisely the six rule types and parameters from
Step 2.

- [ ] **Step 4: Verify GitHub applies the rules to `main`**

Run:

```sh
gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  repos/CtrlCarlitos/agent-guardrails/rules/branches/main
```

Expected: effective rules include pull request, required status checks, signed
commits, linear history, deletion, and non-fast-forward protections. Do not
create a test pull request or exercise the administrator bypass.

- [ ] **Step 5: Record the applied ruleset ID and verification result**

Report the ruleset ID and confirmation that both stored and effective GitHub
responses match the spec. No repository file or git commit is needed because
the ruleset is GitHub-hosted configuration.
