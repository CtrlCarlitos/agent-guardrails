// Package policy defines the guardrail policy model: the shipped Base policy,
// a project's Overlay, and the merge of the two.
package policy

import (
	"fmt"
	"slices"
)

// Capability describes the authority exposed by a native plane tool.
type Capability string

const (
	CapabilityCommand       Capability = "command"
	CapabilityReadDiscovery Capability = "read_discovery"
	CapabilityMutation      Capability = "mutation"
	CapabilityWebFetch      Capability = "web_fetch"
	CapabilityWebSearch     Capability = "web_search"
	CapabilityDelegation    Capability = "delegation"
	CapabilitySafeControl   Capability = "safe_control"
	CapabilityDeny          Capability = "deny"
	CapabilityUnknown       Capability = "unknown"
)

type UnknownToolPosture string

const (
	UnknownAudit UnknownToolPosture = "audit"
	UnknownDeny  UnknownToolPosture = "deny"
)

func ParseUnknownToolPosture(value string) (UnknownToolPosture, error) {
	posture := UnknownToolPosture(value)
	switch posture {
	case UnknownAudit, UnknownDeny:
		return posture, nil
	default:
		return "", fmt.Errorf("invalid unknown_tool_posture %q; want audit or deny", value)
	}
}

type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

func (d Decision) Severity() int {
	switch d {
	case Allow:
		return 0
	case Ask:
		return 1
	case Deny:
		return 2
	default:
		return -1
	}
}

func (d Decision) Blocks() bool { return d == Deny }

// Verdict is the outcome of evaluating one attempted tool call.
type Verdict struct {
	Decision     Decision
	RuleID       string
	OriginRuleID string
	Reason       string
	AuditKind    string
}

func (v Verdict) IsZero() bool { return v.Decision == "" }

// Rule is a data-driven policy rule (used for Overlay [[rules]]; the Base's
// core checks are code in internal/engine).
type Rule struct {
	ID       string
	Tool     string
	Pattern  string
	Decision Decision
	Reason   string
}

// Slots are the parameterized values a Base policy leaves for an Overlay to fill.
type Slots struct {
	SafeRoots       []string
	SecretDirs      []string
	SecretGlobs     []string
	SecretAskGlobs  []string
	SecretAllow     []string
	EgressAllowlist []string
	AuditLog        string
}

// Policy is a fully merged, ready-to-evaluate policy.
type Policy struct {
	Slots              Slots
	Rules              []Rule
	Waived             map[string]bool
	UnknownToolPosture UnknownToolPosture
}

// SortedWaivers returns the ids of active waivers in p, sorted. nil-safe.
func SortedWaivers(p *Policy) []string {
	if p == nil || p.Waived == nil {
		return nil
	}
	var out []string
	for k, v := range p.Waived {
		if v {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
