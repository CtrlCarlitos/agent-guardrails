package policy

import (
	"path/filepath"
	"time"
)

// Operator-issued command grants: a narrower relaxation than the overnight
// one.
//
// Both are an operator-issued, time-boxed relaxation of Ask to Allow. The
// difference is scope -- a grant names one command in one repository under one
// rule -- and that difference is the whole reason the mechanism is acceptable,
// so every part of it is enforced here rather than left to the caller.
//
// A grant never touches a Deny. It converts an Ask the operator has just read
// into an Allow, which is what makes "the operator ran it outside guardrail
// instead" -- the current endgame, and the one action in a session with no
// audit record -- into an in-policy, attributed allow.

const (
	// DefaultGrantExpiry is the window an issuance gets when the operator
	// does not ask for one.
	DefaultGrantExpiry = 30 * time.Minute
	// MaxGrantExpiry bounds every issuance. A relaxation that outlives the
	// operator's attention is one nobody is deciding about any more.
	MaxGrantExpiry = 24 * time.Hour
)

// outwardReachAsks is ADR-0018's exclusion set, and it is deliberately the
// only copy. The overnight relaxation reads it through NeverRelaxable and
// grants read it through NeverGrantable, because the decision behind it --
// the External tier is a per-call operator decision -- is about the tier, not
// about which mechanism is asking to relax it.
//
// ADR-0018 exists because the overnight relaxation silently widened into
// outward reach: it began granting artifact publication, cron creation and
// unknown MCP families, which was never its intent. A grant built without this
// list would reopen that hole through a new door, and more quietly, because a
// grant looks narrow at the point of issue.
var outwardReachAsks = map[string]bool{
	"capability-external":   true,
	"capability-web-search": true,
	"unknown-native-tool":   true,
}

// NeverRelaxable reports whether an Ask stays an Ask no matter which
// operator-issued relaxation is asking (ADR-0018).
func NeverRelaxable(ruleID string) bool { return outwardReachAsks[ruleID] }

// NeverGrantable reports whether a rule can never be covered by a command
// grant: ADR-0018's outward reach, plus the fail-closed backstops that can
// never be waived. Relaxing one of those converts the engine's fail-closed
// design into a fail-open one, and a grant is a relaxation like any other.
func NeverGrantable(ruleID string) bool { return NeverRelaxable(ruleID) || neverWaivable[ruleID] }

// CommandGrant authorizes one exact command, under one rule, in one
// repository.
//
// There is no pattern language and this is a decision, not an omission. A
// pattern implies matching semantics, and matching semantics have been the
// most reliable source of silent failure in this codebase -- `gh repo delete*`
// matched nothing, 23 floor globs were judged against the wrong matcher, and
// the production and test matchers disagree. Each of those failed closed: a
// gate that did not fire. A grant pattern fails the other way, and the agent
// is the party that asks the operator to issue one. Exact match is verifiable
// by reading it; a pattern is not.
type CommandGrant struct {
	RuleID  string `toml:"rule_id"`
	Command string `toml:"command"`
	// Uses is the number of executions still authorized. Absent is zero and
	// zero is exhausted: consumption writes this count back, so reading an
	// absent count as a fresh use would hand a spent grant a new one on every
	// reload. Issuance always writes it explicitly.
	Uses int `toml:"uses"`
	// ExpiresAt is the optional additional bound. Zero records no time bound;
	// the grant is still bounded by Uses, which is the bound that is always
	// present.
	ExpiresAt time.Time `toml:"expires_at"`
}

// RemainingUses reports the executions this grant still authorizes.
func (g CommandGrant) RemainingUses() int {
	if g.Uses < 0 {
		return 0
	}
	return g.Uses
}

// Live reports whether the grant can still authorize a command at now.
func (g CommandGrant) Live(now time.Time) bool {
	if NeverGrantable(g.RuleID) || g.RemainingUses() == 0 {
		return false
	}
	return g.ExpiresAt.IsZero() || now.Before(g.ExpiresAt)
}

// IssuedUses is the use count an issuance records for a requested count.
// Every case in the filing needed exactly one successful pass, so one is the
// default and a larger number is something the operator states.
func IssuedUses(requested int) int {
	if requested < 1 {
		return 1
	}
	return requested
}

// BoundedGrantExpiry is the expiry an issuance records, clamped so that no
// issuance can outlive MaxGrantExpiry regardless of what was asked for.
func BoundedGrantExpiry(now time.Time, requested time.Duration) time.Time {
	if requested <= 0 {
		requested = DefaultGrantExpiry
	}
	if requested > MaxGrantExpiry {
		requested = MaxGrantExpiry
	}
	return now.Add(requested)
}

// GrantKey returns the key in o.Repos under which this repository's grants
// live, or the cleaned path when there is no entry for it yet.
//
// Every writer must go through this rather than indexing the map directly.
// Matching resolves symlinks before declaring no grant -- on Darwin git
// reports the physical repo root (/private/var/...) while a grant may be keyed
// by the symlinked spelling (/var/folders/...) -- so a writer that cleaned the
// path and indexed the map would read and write a *different* entry than the
// matcher read.
//
// The consequence of that split is not a missed match, which would be
// harmless. It is an unspendable one: the grant keeps matching and consumption
// keeps finding nothing to spend, which silently turns a single-use grant into
// an unlimited one. One resolution rule, used by both sides.
func (o *OperatorConfig) GrantKey(repoRoot string) string {
	cleaned := filepath.Clean(repoRoot)
	if o == nil || o.Repos == nil {
		return cleaned
	}
	if _, ok := o.Repos[cleaned]; ok {
		return cleaned
	}
	want := resolvePathForCompare(cleaned)
	for root := range o.Repos {
		if resolved := filepath.Clean(root); resolvePathForCompare(resolved) == want {
			return resolved
		}
	}
	return cleaned
}

// AllowsCommand reports whether a live grant authorizes this exact triple.
//
// The command is compared literally, with no trimming, casing or whitespace
// normalization: the operator authorized a string they could read, and any
// normalization here would authorize strings they did not see.
func (o *OperatorConfig) AllowsCommand(repoRoot, ruleID, command string, now time.Time) bool {
	if NeverGrantable(ruleID) {
		return false
	}
	grant, ok := o.grant(repoRoot)
	if !ok {
		return false
	}
	for _, c := range grant.Commands {
		if c.RuleID == ruleID && c.Command == command && c.Live(now) {
			return true
		}
	}
	return false
}
