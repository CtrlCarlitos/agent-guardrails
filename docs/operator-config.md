# Operator config

The Operator config is machine-scoped authorization outside every repository.
It lets the operator approve narrowly defined ways that a repository's Overlay
may loosen the merged Guardrail Policy. The governing rule is:

> An Overlay may add rules, tighten rules, and fill repository-scoped
> parameters freely. Anything that loosens the Guardrail Policy requires an
> explicit Operator config grant.

An Operator config grant does nothing by itself. The repository's Overlay must
also request the corresponding change. This two-file handshake prevents an
Overlay alone from authorizing weaker protection.

## Location

The Engine reads `guardrail/waivers.toml` from the platform config directory:

- Unix: `$XDG_CONFIG_HOME/guardrail/waivers.toml` when
  `XDG_CONFIG_HOME` is a non-empty absolute path.
- Unix fallback: `$HOME/.config/guardrail/waivers.toml`, conventionally written
  as `~/.config/guardrail/waivers.toml`.
- Windows: `%APPDATA%\guardrail\waivers.toml`, with `APPDATA` set to an
  absolute path.

The file is optional. If it is missing, the Engine uses an empty Operator
config: no loosening is authorized and no error is reported.

## Repository Keys

Each top-level TOML table is one repository grant, keyed by that repository's
absolute path. Both the configured key and the repository root used by the
Engine must be absolute. Each is normalized with the platform's
`filepath.Clean` semantics, then compared for exact string equality.

For example, `/home/alex/src/acme-api/.` and
`/home/alex/src/acme-api` have the same cleaned key. Defining both is an error.
A grant for `/home/alex/src/acme-api` does not match a subrepository, a sibling,
or a similarly prefixed path. Cleaning does not establish filesystem identity:
it does not resolve symlinks or identify repositories by Git remote or content.

This binding is to the cleaned absolute path, not to repository identity. A
repository moved, copied, or cloned to a different path does not carry the
grant to that new path. The grant remains attached to the old path until the
operator removes it, however, and a different repository later occupying that
path inherits the stale grant. Remove or review grants when repositories move,
are deleted, or are replaced; add a new key only after reviewing the Overlay at
the new path.

## Supported Grants

One repository table supports exactly these grants:

- `waive = ["<rule-id>", ...]` authorizes the Overlay to request those exact
  Base policy rule IDs. Other requested IDs remain enforced.
- `egress_allowlist = ["<destination>", ...]` authorizes only those exact
  Overlay egress entries. It does not define destinations by itself.
- `secret_allow = true` authorizes that Overlay's `[slots].secret_allow`
  entries. It does not define the entries itself.
- `audit_log = true` authorizes that Overlay's top-level `audit_log` redirect.
  It does not define the destination itself.

Omitted Boolean grants are false. There is no `safe_root` or `safe_roots`
grant. An Overlay's `safe_roots` entry is accepted without an Operator config
grant only when it resolves inside the repository. The Engine resolves the
repository root and each candidate through existing symlinks; for a path that
does not yet exist, it resolves the nearest existing ancestor. An escape
through `..`, an absolute external path, a symlink, or a resolution failure is
dropped and cannot be authorized.

Egress matching is per entry and case-sensitive: the exact string in the
Overlay must appear in `egress_allowlist` for the exact repository key.
Equivalent host or wildcard spellings do not inherit a grant. Total wildcards
`*` and `**` are forbidden and remain dropped even if the Operator config lists
them. A `P6.egress` Waiver is separate and disables that Base rule rather than
granting a destination.

Three fail-closed backstops are immutable even if both files name them:

- `tokenize-failed`
- `panic-recovered`
- `P3.unresolved`

No operator and no Overlay can waive these rules.

## Worked Example

Suppose the reviewed repository root is `/home/alex/src/acme-api`. Its Operator
config entry is:

```toml
["/home/alex/src/acme-api"]
waive = ["P7.trifecta"]
egress_allowlist = ["api.partner.example"]
secret_allow = true
audit_log = true
```

The repository's committed `guardrail.toml` separately makes the requests:

```toml
audit_log = ".agents/guardrail.jsonl"
waive = ["P7.trifecta"]

[slots]
safe_roots = ["./tmp"]
egress_allowlist = ["api.partner.example"]
secret_allow = ["./fixtures/public-token.txt"]
```

The Operator config authorizes only this exact cleaned repository path. It
allows the requested `P7.trifecta` Waiver, exact egress entry, secret allowance,
and audit redirect. The `safe_roots` entry needs no grant but still must resolve
inside the repository. Keep top-level Overlay fields such as `audit_log` and
`waive` before `[slots]`; placing them after that header would make them slot
fields in TOML.

## Errors and Refusals

A malformed or unreadable Operator config authorizes nothing. The same is true
when its platform config directory is unavailable or relative, any repository
key is relative, or two keys clean to the same path. The Engine rejects the
whole file rather than retaining a partial set of grants, reports the load
error, and continues with an empty Operator config.

An unauthorized Overlay request is also non-fatal. The Engine drops it, keeps
the stricter Guardrail Policy, and emits a specific warning: each refused
Waiver names its rule ID, rejected `safe_roots` entries name their path, and
refused egress entries, `secret_allow`, or `audit_log` requests name the entry
or capability. These
warnings are deterministic policy output, not an implicit Verdict change.
`guardrail doctor` is the universal operator view across all planes and shows
the complete merge-warning list. Claude SessionStart also places a sanitized,
bounded list of up to 20 warnings in its posture. OpenCode and Antigravity have
no SessionStart posture; use Doctor for their complete refusal view.

## Static Enforcement Boundary

The Guardrail Policy protects Operator config from writes visible through a
plane's tool-call boundary. The Engine checks lexical paths and resolved targets
through existing symlinks, including aliases outside the repository. It also
conservatively denies known opaque interpreters when their visible literal code
names an Operator config path. Direct reads remain readable under this
write-only protection.

This is not an operating-system sandbox. Arbitrary same-user code can construct
a protected path dynamically and write it without exposing that target in the
attempted tool call. Such hidden writes are outside static inspection; use
operating-system isolation where that threat must be contained.

## Verify a Grant

Run Doctor from the repository whose grant you are checking:

```sh
guardrail doctor
```

Confirm that the Overlay says `parsed OK`, inspect every entry under `policy
warnings:`, and check the `waivers:` and `audit log:` lines. An effective
Waiver is listed under `waivers:` and also produces a policy warning stating
that the rule is waived by operator authorization. A refused request says
`NOT authorized`, `DROPPED`, or `can never be waived` and states which stricter
behavior remains in force. Operator config load errors are printed separately
and the config is treated as empty.

See [ADR-0010](./adr/0010-operator-scoped-loosening.md) for the trust-model
decision and its rationale.
