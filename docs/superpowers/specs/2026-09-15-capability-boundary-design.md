# Capability Boundary Design

**Status:** agreed with Carlitos 2026-09-15. First production-readiness
increment. Applies to Claude Code, OpenCode, and Antigravity only; Codex is a
separate future adapter project.

## Why

Current adapters explicitly normalize only a subset of each supported plane's
native tools. Other hook-visible tools can silently bypass shell, path, secret,
or egress policy. Native web tools bypass P6 entirely. The system must turn
each plane's visible tool surface into an explicit, tested policy boundary.

## Scope

This increment provides:

- explicit native-tool classification for every hook-visible tool in Claude,
  OpenCode, and Antigravity;
- audit-first, then deny-by-default treatment for unclassified tools;
- a Guardrail-owned web-fetch proxy with hostname enforcement and operator authorization;
- an operator-owned persistent-allowance and operator-action approval broker;
- tested child-context enforcement before delegation is allowed;
- plane contracts, adversarial tests, and documented hosted/opt-out limits.

It does not add a Codex adapter, a remote approval service, browser redirects
as an authorized egress path, a global Base external allowlist, or a sandbox
against arbitrary same-user processes.

## Capability Contract

Each Adapter owns an exhaustive inventory of its hook-visible native tools.
Every entry declares one capability:

- `command`: existing shell policy;
- `read_discovery`: existing direct-read secret/path policy;
- `mutation`: existing edit/write policy;
- `web_fetch`: hostname-aware egress policy;
- `web_search`: operator Ask; no caller-visible destination hostname exists;
- `delegation`: allowed only when child Guardrail inheritance is verified;
- `safe_control`: no filesystem or network authority; explicitly Allow;
- `deny`: known unsupported capability;
- `unknown`: no inventory entry.

The Engine receives the classification and exact native call identity. It never
infers that an absent classification is safe. `unknown` is an audit event in
audit posture and a Deny in deny posture. Every inventory is contract-tested
against the plane's registered hook matcher so a registered native tool cannot
be omitted accidentally.

Command, read/discovery, and mutation capabilities reuse the established Engine
rules. Search, glob, list, and LSP operations that can expose a path use the
same directory-secret, file-secret, and ambiguous-secret treatment as `Read`.
Known tool inputs that do not expose enough data for their capability are Deny.

## Plane Inventory

The implementation inventory begins from the coverage report at
`docs/research/2026-09-15-plane-tool-coverage.md`.

- **Claude Code:** classify Bash and PowerShell as command; Read, LSP, and
  discovery-capable tools as read/discovery; Edit, Write, MultiEdit, and
  NotebookEdit as mutation; WebFetch as web fetch; WebSearch as web search;
  Agent/task tools as delegation after inheritance verification; known MCP
  tools must be classified explicitly or Deny.
- **OpenCode:** classify bash as command; read, list, grep, glob, and LSP as
  read/discovery; edit, write, and apply_patch as mutation; webfetch as web
  fetch; websearch as web search; task as delegation after inheritance
  verification; safe built-ins such as question, skill, and todowrite are
  explicit safe control; custom and MCP tools Deny until classified.
- **Antigravity:** classify run_command as command; view_file, list, find, and
  grep as read/discovery; write and replace operations as mutation;
  read_url_content as web fetch; search_web as web search; subagent tools as
  delegation after inheritance verification; scheduler, permission, media, and
  other known tools are explicitly safe control or Deny according to their
  documented authority.

The exact registered tool inventories must be checked against the current
first-party plane tool references during implementation. Hosted, opt-out, and
unhookable tools are recorded in plane documentation as irreducible limits;
they must never be described as enforced.

## Egress And Authorization

External egress has no shipped Base default. Only localhost remains implicitly
allowed. Native plane web-fetch tools are Deny: none expose redirect-final-host
evidence before execution. Web research instead uses `guardrail fetch <URL>`.
The proxy normalizes the hostname and uses one of four outcomes:

- localhost: Allow;
- exact one-time URL request: Ask;
- exact hostname in an authorized repository allowance: Allow;
- exact hostname in an operator-owned global allowance: Allow;
- all other external hosts: Ask.

Persistent allowances accept exact hostnames only. URLs, paths, ports,
wildcards, and redirect destinations are not persistent allowance values.
The proxy validates every redirect hop before following it; an unapproved final
destination stops the fetch and never inherits authorization. It supports only
unauthenticated HTTP(S) GET, sends no cookies, credentials, bodies, proxy
settings, or arbitrary headers, accepts text/HTML/Markdown/JSON, normalizes HTML
to text, caps output at 1 MiB, and returns normalized text on stdout. Web search
remains Deny until its provider endpoint can be independently verified.

An agent may request an allowance but never writes it. The operator can choose
one-time, repository, global, or deny. Repository scope records a hostname in
the project's Overlay plus its machine-scoped Operator authorization for the
exact repository path. Global scope exists only in machine-scoped Operator
config. Allowance creation, revocation, and every allowance hit are audited.
`guardrail fetch` is the sole Guardrail subcommand callable by agents; all other
Guardrail configuration commands remain Deny unless broker-executed operator
actions.

## Trusted Approval Broker

Persistent allowance requests use a Guardrail-owned broker rather than model
text or OpenCode's inferred retry approval.

Each request is bound to plane, session, repository path, hostname, requested
scope, reason, random request identity, and a short expiry. It is single-use.
The broker renders the exact request through the first available trusted local
transport:

- desktop: a local loopback browser page with Allow repository, Allow global,
  Allow once, and Deny controls;
- headless: an operator opens a separate SSH terminal and runs
  `guardrail approvals --request <id>`, receiving the same fields and choices.

The response reaches Guardrail directly. The coding agent sees only pending,
approved, denied, or expired state. The agent cannot select a persistent scope,
forge a response, or convert a one-time Ask into a permanent grant. If no
trusted transport resolves a request before expiry, it remains denied. Remote
approval from another device is out of scope.

The broker is a user-level daemon, started on demand when a hook submits a
request and no authenticated local broker socket exists. Hooks submit requests
to the daemon and exit; they never host the browser server. The daemon owns
protected pending state, serves the loopback page, executes approved actions,
and accepts the headless SSH TUI as another client. It exits after ten minutes
with no pending requests, active browser/TUI clients, or activity. A pending
request keeps it alive until it is approved, denied, or expires.

The first broker implementation supports Unix/WSL and macOS through a mode-0700
Unix socket directory for hook and TTY clients. Windows persistent/operator
approval is explicitly unsupported and fails closed until a native Windows
implementation validates its current-user named pipe ACL, browser launch, and
interactive approval behavior. Hooks can submit requests but cannot approve
them. Each browser request
receives a random 256-bit, single-use bearer token bound to its request and
expiry. The daemon opens its tokenized loopback URL directly through the OS
browser launcher; it never prints, audits, persists, or returns that URL to the
agent. Browser approval requires the token and loopback origin. The daemon
starts again if its socket is absent or stale. This resists the coding agent in
the Guardrail tool-level threat model, not arbitrary malware running as the
same OS user.

## Operator-Authorizable Actions

The broker also owns a deliberately small registry of privileged operations
that an agent may request but never execute. Initial entries are night mode
on/off and persistent web-host grant/revoke. Every other Guardrail
self-configuration mutation remains an unconditional Deny.

The only canonical agent-requestable persistent-host forms are:

```text
guardrail egress grant --scope repo|global --host <exact-host>
guardrail egress revoke --scope repo|global --host <exact-host>
```

The parser rejects reordered/extra arguments, shell extensions, URLs, ports,
paths, wildcards, and non-canonical hostnames. Requested scope is immutable and
shown verbatim to the operator; approval cannot broaden it. One-time fetch
authorization remains a separate `guardrail fetch` approval path.

An adapter recognizes a registered operator-action request and sends its exact,
canonical parameters to the broker. It blocks the originating tool call. On
operator approval, the broker executes the internal operation itself, audits
the request and mutation, and records completion. The agent receives only that
the action completed, was denied, or expired; it never retries or directly
executes the privileged shell command. This differs from a normal Ask retry,
which is unsuitable for self-configuration.

## Delegation

Native task/subagent tools are not a bypass. Each plane must prove, through an
integration test, that a spawned child receives active Guardrail registration
and its own session identity before delegation is Allowed. If inheritance is
missing, unverifiable, or changes in a plane update, delegation is Deny.

## Rollout

The new capability boundary begins in operator-selected `audit` posture.
Unclassified hook-visible calls retain existing behavior but generate a distinct
audit event containing plane, native tool, session, and safely bounded input
shape. No native tool is added to the final inventory solely from telemetry;
each classification needs explicit review and tests.

After all three plane inventories are complete and the audit log records no
unclassified tool events for fourteen consecutive days, the operator enables
`deny` posture. In deny posture every unclassified pre-execution tool call is
blocked. The posture, transition, and unknown-tool events are visible in
doctor/session status and audited.

## Error Handling And Testing

Malformed tool inputs, missing path/URL fields, unknown capability values,
broker failures, expired requests, and failed delegation inheritance all deny.
Broker state changes are atomic and do not expose raw sensitive arguments in
state files.

Tests cover Engine capability dispatch, path/secret behavior through discovery
tools, URL normalization, scope isolation, one-time and persistent approval,
broker expiry/replay resistance, adapter wire protocols, each plane inventory,
child inheritance, audit posture, deny posture, generated configuration, and
adversarial bypass attempts. Real installed-plane smoke tests verify desktop
and headless approval transports before deny posture is enabled.

## Follow-on Workstreams

This increment precedes but does not include:

- removal of duplicate Claude hooks, audit rotation, and documented rollback;
- a non-dev release boundary, provenance/SBOM, and deployed-plane validation;
- Dependabot/code scanning, SHA-pinned Actions, and repository governance;
- Codex adapter design and implementation.
