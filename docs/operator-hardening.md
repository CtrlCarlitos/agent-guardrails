# Operator hardening

guardrail and the agent share a trust domain. Every rule in the Engine catches
mistakes and leaves an audit trail, and that is worth having — but a rule is
something the agent runs inside. The strongest control is the one it cannot
reach at all:

> **The agent's credential simply lacks the authority.**

This page is about arranging that. None of it is enforced by guardrail; all of
it is enforced by GitHub, your cloud provider, or your biller, which is exactly
why it holds when guardrail does not.

State the limit plainly, because it is easy to assume otherwise: **guardrail
protects secrets from being *read*. It does not, by itself, stop ambient
authority from being *used*.** A token already in the environment is authority
the agent holds without ever reading a secret file.

## 1. Run agents under a reduced GitHub credential

Create a **fine-grained personal access token**, scoped to selected
repositories:

| Permission | Setting |
|---|---|
| Contents | Read and write |
| Pull requests | Read and write |
| Issues | Read and write |
| Actions | Read |
| Administration | **No access** |
| Secrets | **No access** |
| Workflows | **No access** |
| Environments | **No access** |

Export it as `GH_TOKEN` in the agent's launcher — `gh` prefers it over the
stored login, so the agent gets the reduced credential while your own
interactive `gh` keeps yours:

```sh
GH_TOKEN=github_pat_… claude
```

Protection changes then return `403` for the agent, and making one becomes a
deliberate act you perform yourself. That is the difference between a rule that
asks and a wall that refuses.

**Check it took effect.** `guardrail doctor` prints a `credential posture:`
section and names any credential variables that are set, because a token in the
environment overrides the stored login — so the login you hardened may not be
the one in play.

## 2. One identity per machine context

Do not keep an employer account logged into the same `gh` as personal agent
sessions. With more than one account logged in, which one an agent acts as
depends on the active account and on the environment, so the reach of any given
call is not fixed by what you last checked. `guardrail doctor` warns when it
sees more than one.

## 3. Hard caps at the provider

A spend limit enforced by the biller holds regardless of what any local tool
does, including this one.

- **GitHub**: set budgets to `$0` with stop-usage for Actions, Codespaces and
  Packages.
- **Every metered API key in the environment**: prepaid credit, or a per-key
  spend limit.

This is the only control on this page that bounds a runaway loop rather than a
single decision.

## 4. Server-side invariants the reduced token cannot touch

Set these once, from your own credential. A token without Administration
cannot undo them:

- Rulesets on the default branch **without bypass actors** — a bypass actor is
  how a ruleset stops applying to the account that has it.
- Tag rulesets, so a release pointer cannot be moved after the fact.
- Immutable releases.
- `sha_pinning_required` for Actions, so a mutable tag cannot change what CI
  runs.
- An Actions allowlist, rather than permitting any action.

## 5. Non-GitHub credentials

The same shape applies, and guardrail can say less about it:

- **Cloud**: give the agent a role with the permissions its work needs, not an
  administrator key. `guardrail doctor` reports that a cloud credential
  variable is *set* but deliberately does **not** claim to judge how privileged
  it is — establishing that requires calling the provider, which doctor does
  not do. A check that guessed would hand you false assurance, which is worse
  than no check.
- **Kubernetes**: keep the agent's kubeconfig pointed at a local cluster.
  `guardrail doctor` warns when the current context is not a known-local one
  (`kind-`, `minikube`, `docker-desktop`, `k3d-`, `rancher-desktop`), using the
  same list the Engine uses to judge a `kubectl` command, so the two cannot
  disagree about what local means.

## What `guardrail doctor` reports

Under `credential posture:`, all advisory — doctor never fails on any of it:

- the `gh` login carrying administration-shaped scopes (`admin:*`,
  `delete_repo`, `workflow`, `write:org`, `site_admin`)
- more than one `gh` account logged in
- credential variables that are set, **by name only**
- a kubectl context that is not known-local

Doctor learns all of this **without reading or printing credential material** —
scope names, account counts and variable names only. If it cannot learn
something, it says nothing about it: silence in this section means *not known*,
never *fine*.

`repo` is deliberately not warned about. Nearly every working login carries it,
and a warning everybody sees every time is how an operator learns to click
through the ones that matter. Narrowing it is what the fine-grained token in
§1 is for.

## Related

- [ADR-0010](./adr/0010-operator-scoped-loosening.md) — the operator trust model
- [ADR-0022](./adr/0022-degraded-mode-floor-fallback.md) — what still applies when the
  Engine is unreachable
- [Operator config](./operator-config.md) — waivers, grants and their scoping
