# ADR-0033: Operator approvals default to a prompt; the passkey is opt-in

## Status

Accepted (operator decision on #413, 2026-09-27). Amends ADR-0021 and
ADR-0025 (the broker is no longer the default approval channel), ADR-0027
(egress and plane actions gain a second approval channel), and ADR-0030
(in prompt mode, loosening actions need an approval, not an enrollment).
Passkey mode keeps all four exactly as written.

## Context

Every persistent operator action (`setup`, `plane enable|disable`,
`recover`, `web-research on|off`, and the brokered `night on|off` and
`egress grant|revoke`) completes only after a WebAuthn ceremony in a browser.
The operator finds that too heavy for day-to-day use: most approvals are
"yes, I asked for that", and the question should appear where they already
work, not on a loopback page.

What happens today, measured on `d274a8e` in a sandboxed state root:

- An agent that runs `guardrail plane enable claude` through the Claude hook
  is denied `P5.self-config` (exit 2). There is no way to ask for it.
- `guardrail night off` and `guardrail egress grant …` issued by an agent
  are caught by the hook (`engine.OperatorAction`), filed with the approval
  broker, and returned as a `Complete` verdict: a deny carrying
  `operator_action`, `request_id` and an approval URL. The daemon applies the
  action after the passkey.
- From a terminal, `setup`, `plane`, `recover` and `web-research` file a
  broker request and poll for it; `night` and `egress` apply directly, the
  terminal being the proof of presence.
- With no terminal: `setup`/`plane enable` arm by bootstrap when nobody is
  enrolled (ADR-0030); everything else exits 3 (or 2 for `recover`).

Two findings from measuring the mitigations #413 relies on:

1. The claim "an agent cannot fake a TTY through a pty wrapper" held only for
   interpreters. `python3 -c 'import pty; pty.spawn(...)'` naming guardrail and
   a lifecycle word is denied, but `script -qc "guardrail setup" /dev/null`,
   `expect -c 'spawn guardrail setup'`, `unbuffer guardrail setup`,
   `winpty guardrail setup`, `tmux new-session -d 'guardrail setup'` and
   `screen -dm guardrail setup` were all **allowed** by the engine. With a
   passkey that was harmless (a TTY alone approves nothing), and the TTY
   *alone* was already enough for `night` and `egress` from a terminal. With a
   `[y/N]` prompt it would not be harmless: the wrapper supplies the TTY and
   the agent types the `y`.
2. `egress` is not in the self-control set: a non-canonical spelling
   (`guardrail egress grant … ; true`) passes the engine and reaches the CLI,
   which only its TTY gate stops. `winpty guardrail egress grant …` was
   allowed.

And one about where state lives: P5 does not protect the whole state root.
It protects `…/guardrail/sessions/**`, `waivers.toml`, `night.toml` and
`.config/guardrail/**`. A new store must get its own protected path.

## Decision

### The mode

1. Operator config gains one top-level key, `approval = "prompt" | "passkey"`.
   Missing means `"prompt"`, for everyone, including operators who already
   enrolled a passkey. An unknown value is a configuration error.
2. Only Operator config can set it. An Overlay has no such key and the merge
   never reads one; a repository cannot choose how its own agent's operator
   actions are approved.
3. When the Operator config cannot be read or parsed, the mode is `passkey`,
   the stronger one. A damaged file must not downgrade an operator who chose
   the passkey. (With no enrolled passkey that means today's exit 3, which
   the operator fixes by repairing the file.)
4. `passkey` is today's behaviour, byte for byte: the broker, the WebAuthn
   ceremony, `Complete` verdicts for night and egress, `P5.self-config` for
   lifecycle commands from a session, the enrollment preflights.

### Prompt mode: an agent asks through its host

5. The hook recognises a closed set of **canonical operator commands**, whole
   commands only, under the same whitelist grammar as the existing egress
   parser (lowercase letters, digits, `.`, `,`, `=`, `-`, `:` and single
   spaces; no quoting, substitution, chaining, redirection):
   `guardrail setup [--state enabled|disabled] [--planes <list>]`,
   `guardrail plane enable|disable <plane>|--all`,
   `guardrail recover <repair>`, `guardrail web-research on|off`,
   `guardrail night off`, `guardrail night on --until HH:MM`, and
   `guardrail egress grant|revoke --scope … --host …`.
   Anything else that names these subcommands stays `P5.self-config`.
6. For a canonical command the hook returns the plane's native ask with a
   question that names the action (`ask` on Claude, `force_ask` on
   Antigravity) and records an **approval ticket** (below). Night mode and
   command grants never relax it.
7. opencode raises its dialog only where its own permission config asks.
   When the plugin reports that the human approved this exact call
   (`host_approved`, ADR-0015), the hook records the ticket and allows the
   call. Otherwise it returns an ask whose text tells the agent to have the
   operator run the command in a terminal; the ADR-0011 retry inference does
   not apply to operator actions.
8. Codex cannot surface an ask from a hook (ADR-0014; on Windows, #349).
   The hook denies with rule `operator-action-terminal` and names the exact
   command for the operator to run in a terminal. No ticket.

### The ticket: how a TTY-less CLI run proves the host's approval

After the human approves, the host runs the command with no terminal, so the
CLI needs proof that this run was approved.

9. **Where.** `<state>/guardrail/approval-tickets/`, under the state root
   (`%LOCALAPPDATA%` on Windows, `$XDG_STATE_HOME` or `~/.local/state`
   elsewhere), created owner-only. P5 gains `**/guardrail/approval-tickets`
   and `…/**` as protected write paths, and interpreter code naming that
   directory is denied like interpreter code naming the Operator config.
10. **What.** One JSON file per ticket: canonical command, canonical working
    directory, repository root, plane, a SHA-256 digest of the session ID,
    issue time and expiry. No secret: a ticket is honoured because of *where*
    it is and *what it binds*, and writing there is what P5 denies.
11. **Key.** The file name is `<session digest prefix>-<binding digest>.json`,
    where the binding digest is SHA-256 over a versioned, length-prefixed
    tuple of the canonical command and the canonical working directory
    (absolute, cleaned, symlinks resolved, case-folded on Windows). The CLI
    rebuilds the command from its own argv (`guardrail ` + the arguments
    joined by one space; the whitelist grammar makes that reconstruction
    exact) and its own working directory, so it can only find a ticket for
    the command it is actually running, where it is running.
12. **Lifetime.** Ten minutes from the ask, the window the ask guidance
    already uses. Expired tickets are removed when seen.
13. **Single use.** The CLI claims a ticket by renaming it to a
    process-unique name; exactly one concurrent claimant wins the rename. It
    then re-validates the contents (version, expiry, command, working
    directory) and deletes it. A claimed ticket is gone whether or not the
    action then succeeds.
14. **Voiding.** Any other pre-execution hook call from the same session
    deletes that session's outstanding tickets. After an approval the host
    runs the approved command next, with no hook call in between; after a
    denial the agent's next action voids the ticket rather than leaving it
    live for ten minutes. A re-issue of the same canonical command replaces
    its ticket instead of voiding it.
15. **Application.** A CLI run in prompt mode resolves its approval in this
    order: a valid ticket (transport `host-ask`); else a terminal prompt
    (`Approve <summary>? [y/N]`, default No, transport `terminal-prompt`);
    else refuse with exit 3, as today. An approved action runs the same
    registered action handler the broker would run, in-process, with the
    same audit journal, so `guardrail audit` shows an `operator-action`
    record with the transport that approved it. `night` and `egress` keep
    applying directly from a terminal, as today; the ticket additionally lets
    them apply without one.
16. **Bootstrap.** ADR-0030 stands: with no terminal, no ticket and no
    enrolled passkey, `setup` and `plane enable` still arm the planes and can
    only tighten. With a terminal, prompt mode asks first. In prompt mode the
    loosening actions (`--state disabled`, `plane disable`, `recover`,
    `web-research off`) need an approval (prompt or ticket), not an
    enrollment; the legacy floor is pruned only when an approval is obtained.

### Closing the fake-TTY path

17. `script`, `expect`, `unbuffer`, `winpty`, `tmux`, `screen`, `socat`,
    `dtach`, `abduco`, `empty`, `faketty`, `mintty`, `wt` and `conhost` join
    the interpreters as opaque executors for the self-control rule: their
    command text naming guardrail and a self-control subcommand is
    `P5.self-config`, in both modes.
18. `egress` and `hook` join the self-control subcommands. The canonical
    egress command is intercepted before evaluation (5), so only
    non-canonical spellings are denied. A session never needs to run
    `guardrail hook` itself; running it would let it forge the host's hook
    payload and mint a ticket without an ask.

## Why this is sound, and where it stops

Within the engine's static boundary (ADR-0012, ADR-0019), an agent cannot
reach an approved operator action without a host prompt that a human or a
host auto-approve answered yes:

- The only visible spelling that reaches the CLI is the canonical command,
  and the hook intercepts it and asks. Every other spelling, every wrapper
  that could supply a TTY, and every interpreter naming the command, is
  denied (17, 18).
- A ticket cannot be written: its directory is a P5 path (9). It cannot be
  minted without an ask: the hook is the only writer and a session cannot
  invoke the hook (18). It cannot be replayed: it is claimed by an atomic
  rename and deleted (13). It cannot be redirected: it binds the exact
  command and working directory (11). A denied ask leaves it live only until
  the session's next call (14) and never past ten minutes (12).

What it does not stop, stated so no one plans against it:

- **Host auto-approve (accepted in #413).** Claude `bypassPermissions` or an
  always-allow rule matching the command, and Codex full-auto, answer the ask
  yes with no human. An agent in such a session can change guardrail's own
  settings. Mitigations: agents cannot edit host settings (P5), so they
  cannot grant themselves that mode; the ask names the action and the audit
  record names the transport; passkey mode remains for operators who need a
  human in every approval.
- **Unseen execution paths.** A same-user process the engine cannot see into
  (a script file, a build tool, a background job started earlier) can run
  the CLI, claim a pending ticket before the human answers, or feed the hook
  a forged payload. That is the boundary every other guardrail rule already
  has ("Guardrail is not an OS sandbox"), and it is why the passkey exists:
  a WebAuthn user-verification gesture cannot be scripted. In prompt mode
  the session-scoped voiding (14) and the ten-minute bound (12) limit, but do
  not remove, this exposure.

## Considered alternatives

- **Apply the action in the PostToolUse hook** (the tool ran, so it was
  approved). Rejected: it needs the CLI to exit 0 and "succeed" without doing
  anything, PostToolUse semantics differ per plane, and it is no stronger
  against a forged hook payload.
- **A secret nonce injected into the approved command** (`updatedInput`).
  Not every plane can rewrite a command it is about to ask about, and
  whether the model can read the rewritten input after a denial is not
  something we can measure; it would not generalise to Antigravity or
  opencode.
- **Bind the ticket to the host process ancestry.** Ancestry is unreliable
  across Git Bash, WSL and PowerShell, costly to read on Windows, and an
  unseen path started from the same host has the same ancestry.
- **Keep passkey as the default and make prompt opt-in.** Rejected by the
  operator: the approval most people need is presence, and the passkey stays
  one line away.

## Consequences

- A fresh or upgraded install asks in the host or on the terminal instead of
  opening a browser. `guardrail doctor` prints `approval mode: prompt` or
  `approval mode: passkey`.
- Adding `approval` to `waivers.toml` makes the file unreadable to a binary
  older than this change, which then treats Operator config as empty.
  Downgrading after setting the key needs the key removed.
- The Operator config format gains a key; the stability policy records it.
- #87 (a desktop notification for the approval page) is no longer needed in
  prompt mode: the question appears where the operator already works.
