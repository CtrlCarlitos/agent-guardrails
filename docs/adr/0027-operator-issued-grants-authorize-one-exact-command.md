# ADR-0027: Operator-Issued Grants Authorize One Exact Command

## Status

Accepted

## Context

Ask verdicts on Windows were unsatisfiable deadlocks: no approval channel was
reachable mid-session, so blocked work exited the guardrail to proceed (#168,
"3 attempts, 0 passes"). Night mode already converts in-session Asks to
Allow, but it is floor-wide - ADR-0018 exists because night mode silently
widened into outward reach once before. The gap was a narrower instrument:
the operator pre-authorizes exactly one action, once, from a terminal,
without relaxing anything else.

The design note on #173 proposed three changes; the operator ruling accepted
all three, plus two follow-ups recorded during implementation (#272).

## Decision

1. **Grants inherit ADR-0018's exclusions from one list.** Night mode and
   grants both relax only in-session asks, so both read
   `policy.NeverRelaxable`; `capability-external`, `capability-web-search`,
   and `unknown-native-tool` are never grantable.
   `policy.NeverGrantable` additionally excludes fail-closed backstops -
   a grant is a relaxation, and relaxing a backstop makes the engine fail
   open. Enforced at issuance and at match time, so a hand-written entry or
   one left by an older binary still cannot relax outward reach.
   `TestBothRelaxationsShareOneExclusionList` fails if the mechanisms drift.

2. **Exact matching, no pattern language.** A grant binds the tuple
   (repository, rule ID, exact command text). `git push origin HEAD:main`
   is not covered by a grant for `git push origin main`, and attempting it
   does not spend the grant - a near-miss must never be a way to disarm an
   authorization. Rationale: every matcher divergence this cycle
   (#244's test-model artifact, #270's literal braces, the #173 filing's
   own evidence) failed closed when the engine owned the matcher, but a
   grant pattern would fail open, and the agent is the party requesting
   the grant. Exact text is verifiable by reading it.

3. **One use by default.** The grant is spent under the operator lock before
   the verdict changes, so concurrent calls cannot both spend one.
   `--for` defaults to 30m and is clamped to 24h.

4. **The ceremony shows the command whole, then quoted**, so tabs and
   trailing spaces are visible. Nothing truncated; no summary stands in for
   the matched string. Issuance is refused outside an interactive operator
   terminal.

5. **Storage lives in `OperatorConfig.Repos` only** - a documented exception
   to the two-file handshake. The handshake's Overlay half would publish
   every authorized command into version control, exposing operational
   command text and the request surface to repo collaborators; a grant is
   operator machinery, not project policy. The two-signal strength is
   preserved through the locked journal transaction plus the terminal
   requirement.

6. **`revoke` ships with the mechanism.** Expiry-only exit is wrong for a
   mechanism adjacent to standing authorization.

7. **Matcher and consumption writer key through
   `OperatorConfig.GrantKey`.** macOS surfaced the lesson: symlinked repo
   roots resolve to different spellings on each side, and a grant that
   matches on one spelling while consumption writes another becomes an
   unspendable authorization - still matching, never spent, effectively
   unlimited.

## Consequences

- The deadlock class converts into a working ceremony: ask, operator grants
  the exact command from a terminal, the call proceeds once.
- ADR-0018's exclusion list is now load-bearing for two relaxation
  mechanisms; it changes only with both in view.
- Grant issuance and consumption are audited; a spent grant is visible in
  the audit log.
- Floor generation must never copy pattern syntax through to a host that
  does not implement it (#270) - the same exactness principle the grant
  matcher applies to authorization applies to the Declarative floor's
  emitted rules.
