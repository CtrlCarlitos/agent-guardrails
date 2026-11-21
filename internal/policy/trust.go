package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// TrustSnapshot records the exact Overlay loosening requests an operator
// bulk-authorized for a repository via `guardrail operator trust` (#131).
// Manual RepoGrant fields remain honored alongside Trust so existing
// waivers.toml entries and `guardrail egress grant` keep working without a
// breaking migration.
type TrustSnapshot struct {
	EgressAllowlist []string `toml:"egress_allowlist,omitempty" json:"egress_allowlist,omitempty"`
	WebHosts        []string `toml:"web_hosts,omitempty" json:"web_hosts,omitempty"`
	Waive           []string `toml:"waive,omitempty" json:"waive,omitempty"`
	SecretAllow     []string `toml:"secret_allow,omitempty" json:"secret_allow,omitempty"`
	AuditLog        string   `toml:"audit_log,omitempty" json:"audit_log,omitempty"`
}

// TrustItem identifies one operator-gated Overlay loosening request in a diff.
type TrustItem struct {
	Kind  string // egress_allowlist, web_hosts, waive, secret_allow, audit_log
	Value string
}

// TrustDiff compares a repository's current Overlay requests against the
// operator's current authorization (trust snapshot and manual RepoGrant).
type TrustDiff struct {
	HasSnapshot bool
	Authorized  []TrustItem
	Pending     []TrustItem
	Removed     []TrustItem
	Rejected    []TrustItem
}

// TrustSnapshotFromOverlay extracts every valid, authorizable loosening request
// from ov into a normalized, sorted, deduplicated snapshot. Backstops
// (neverWaivable), wildcard egress entries (* and **), and invalid web hosts
// are never included.
func TrustSnapshotFromOverlay(ov *Overlay) *TrustSnapshot {
	if ov == nil {
		return &TrustSnapshot{}
	}
	snap := &TrustSnapshot{}
	for _, entry := range ov.EgressAllowlist {
		if entry == "" || entry == "*" || entry == "**" || hasControlChars(entry) {
			continue
		}
		snap.EgressAllowlist = append(snap.EgressAllowlist, entry)
	}
	for _, host := range ov.WebHosts {
		if ValidateWebHost(host) != nil {
			continue
		}
		snap.WebHosts = append(snap.WebHosts, host)
	}
	for _, ruleID := range ov.Waive {
		if ruleID == "" || neverWaivable[ruleID] || hasControlChars(ruleID) {
			continue
		}
		snap.Waive = append(snap.Waive, ruleID)
	}
	for _, glob := range ov.SecretAllow {
		if glob == "" || hasControlChars(glob) {
			continue
		}
		snap.SecretAllow = append(snap.SecretAllow, glob)
	}
	if ov.AuditLog != "" && !hasControlChars(ov.AuditLog) {
		snap.AuditLog = ov.AuditLog
	}
	snap.normalize()
	return snap
}

func (t *TrustSnapshot) normalize() {
	if t == nil {
		return
	}
	t.EgressAllowlist = sortedUnique(t.EgressAllowlist)
	t.WebHosts = sortedUnique(t.WebHosts)
	t.Waive = sortedUnique(t.Waive)
	t.SecretAllow = sortedUnique(t.SecretAllow)
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	slices.Sort(out)
	return slices.Compact(out)
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// IsEmpty reports whether the snapshot carries zero loosening authorizations.
func (t *TrustSnapshot) IsEmpty() bool {
	return t == nil || (len(t.EgressAllowlist) == 0 && len(t.WebHosts) == 0 && len(t.Waive) == 0 && len(t.SecretAllow) == 0 && t.AuditLog == "")
}

// Clone returns a deep copy of t (or nil when t is nil).
func (t *TrustSnapshot) Clone() *TrustSnapshot {
	if t == nil {
		return nil
	}
	return &TrustSnapshot{
		EgressAllowlist: append([]string(nil), t.EgressAllowlist...),
		WebHosts:        append([]string(nil), t.WebHosts...),
		Waive:           append([]string(nil), t.Waive...),
		SecretAllow:     append([]string(nil), t.SecretAllow...),
		AuditLog:        t.AuditLog,
	}
}

// Equal reports whether t and other represent the same normalized trust set.
func (t *TrustSnapshot) Equal(other *TrustSnapshot) bool {
	if t == nil && other == nil {
		return true
	}
	if t == nil || other == nil {
		return false
	}
	a, b := t.Clone(), other.Clone()
	a.normalize()
	b.normalize()
	return slices.Equal(a.EgressAllowlist, b.EgressAllowlist) &&
		slices.Equal(a.WebHosts, b.WebHosts) &&
		slices.Equal(a.Waive, b.Waive) &&
		slices.Equal(a.SecretAllow, b.SecretAllow) &&
		a.AuditLog == b.AuditLog
}

// Validate rejects wildcards, fail-closed backstops, invalid web hosts, empty
// list entries, and control characters so a trust snapshot cannot weaken
// non-authorizable invariants.
func (t TrustSnapshot) Validate() error {
	for _, entry := range t.EgressAllowlist {
		if entry == "" || entry == "*" || entry == "**" || hasControlChars(entry) {
			return fmt.Errorf("invalid trust snapshot egress_allowlist entry %q", entry)
		}
	}
	for _, host := range t.WebHosts {
		if err := ValidateWebHost(host); err != nil {
			return fmt.Errorf("invalid trust snapshot web_hosts entry %q: %w", host, err)
		}
	}
	for _, ruleID := range t.Waive {
		if ruleID == "" || neverWaivable[ruleID] || hasControlChars(ruleID) {
			return fmt.Errorf("invalid trust snapshot waive entry %q", ruleID)
		}
	}
	for _, glob := range t.SecretAllow {
		if glob == "" || hasControlChars(glob) {
			return fmt.Errorf("invalid trust snapshot secret_allow entry %q", glob)
		}
	}
	if hasControlChars(t.AuditLog) {
		return fmt.Errorf("invalid trust snapshot audit_log")
	}
	return nil
}

// Summary returns a concise single-line operator-readable description of the
// snapshot for prompts and the WebAuthn approval page.
func (t *TrustSnapshot) Summary() string {
	if t == nil || t.IsEmpty() {
		return "revoke repository Overlay trust snapshot"
	}
	snap := t.Clone()
	snap.normalize()
	var parts []string
	if len(snap.EgressAllowlist) > 0 {
		parts = append(parts, "egress_allowlist=["+strings.Join(snap.EgressAllowlist, ", ")+"]")
	}
	if len(snap.WebHosts) > 0 {
		parts = append(parts, "web_hosts=["+strings.Join(snap.WebHosts, ", ")+"]")
	}
	if len(snap.Waive) > 0 {
		parts = append(parts, "waive=["+strings.Join(snap.Waive, ", ")+"]")
	}
	if len(snap.SecretAllow) > 0 {
		parts = append(parts, "secret_allow=["+strings.Join(snap.SecretAllow, ", ")+"]")
	}
	if snap.AuditLog != "" {
		parts = append(parts, "audit_log="+snap.AuditLog)
	}
	return strings.Join(parts, "; ")
}

// EncodeTrustSnapshot serializes t (or nil for revocation as "null") after
// validation and normalization.
func EncodeTrustSnapshot(t *TrustSnapshot) (string, error) {
	if t == nil {
		return "null", nil
	}
	snap := t.Clone()
	snap.normalize()
	if err := snap.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// DecodeTrustSnapshot validates a brokered trust snapshot at consent and apply
// time. JSON null represents revocation (removing the repo's trust snapshot).
func DecodeTrustSnapshot(text string) (*TrustSnapshot, error) {
	if len(text) > 64<<10 {
		return nil, fmt.Errorf("trust snapshot exceeds review budget")
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	var snap *TrustSnapshot
	if err := decoder.Decode(&snap); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing trust snapshot input")
	}
	if snap != nil {
		if err := snap.Validate(); err != nil {
			return nil, err
		}
		snap.normalize()
	}
	return snap, nil
}

// DiffTrust compares an Overlay's requested loosenings against op's current
// authorization for repoRoot (both TrustSnapshot and manual RepoGrant entries).
func DiffTrust(ov *Overlay, op *OperatorConfig, repoRoot string) TrustDiff {
	snap, hasSnap := op.TrustFor(repoRoot)
	diff := TrustDiff{HasSnapshot: hasSnap}

	curEgress := map[string]bool{}
	curWebHosts := map[string]bool{}
	curWaive := map[string]bool{}
	curSecret := map[string]bool{}
	curAudit := ""

	if ov != nil {
		for _, entry := range sortedUnique(ov.EgressAllowlist) {
			if entry == "" || entry == "*" || entry == "**" || hasControlChars(entry) {
				diff.Rejected = append(diff.Rejected, TrustItem{Kind: "egress_allowlist", Value: entry})
				continue
			}
			curEgress[entry] = true
			item := TrustItem{Kind: "egress_allowlist", Value: entry}
			if op.AllowsEgress(repoRoot, entry) {
				diff.Authorized = append(diff.Authorized, item)
			} else {
				diff.Pending = append(diff.Pending, item)
			}
		}
		for _, host := range sortedUnique(ov.WebHosts) {
			if ValidateWebHost(host) != nil {
				diff.Rejected = append(diff.Rejected, TrustItem{Kind: "web_hosts", Value: host})
				continue
			}
			curWebHosts[host] = true
			item := TrustItem{Kind: "web_hosts", Value: host}
			if op.AllowsWebHost(repoRoot, host) {
				diff.Authorized = append(diff.Authorized, item)
			} else {
				diff.Pending = append(diff.Pending, item)
			}
		}
		for _, ruleID := range sortedUnique(ov.Waive) {
			if ruleID == "" || neverWaivable[ruleID] || hasControlChars(ruleID) {
				diff.Rejected = append(diff.Rejected, TrustItem{Kind: "waive", Value: ruleID})
				continue
			}
			curWaive[ruleID] = true
			item := TrustItem{Kind: "waive", Value: ruleID}
			if op.AllowsWaiver(repoRoot, ruleID) {
				diff.Authorized = append(diff.Authorized, item)
			} else {
				diff.Pending = append(diff.Pending, item)
			}
		}
		for _, glob := range sortedUnique(ov.SecretAllow) {
			if glob == "" || hasControlChars(glob) {
				diff.Rejected = append(diff.Rejected, TrustItem{Kind: "secret_allow", Value: glob})
				continue
			}
			curSecret[glob] = true
			item := TrustItem{Kind: "secret_allow", Value: glob}
			if op.AllowsSecretAllowEntry(repoRoot, glob) {
				diff.Authorized = append(diff.Authorized, item)
			} else {
				diff.Pending = append(diff.Pending, item)
			}
		}
		if ov.AuditLog != "" {
			if hasControlChars(ov.AuditLog) {
				diff.Rejected = append(diff.Rejected, TrustItem{Kind: "audit_log", Value: ov.AuditLog})
			} else {
				curAudit = ov.AuditLog
				item := TrustItem{Kind: "audit_log", Value: ov.AuditLog}
				if op.AllowsAuditLogPath(repoRoot, ov.AuditLog) {
					diff.Authorized = append(diff.Authorized, item)
				} else {
					diff.Pending = append(diff.Pending, item)
				}
			}
		}
	}

	if hasSnap && snap != nil {
		for _, entry := range sortedUnique(snap.EgressAllowlist) {
			if !curEgress[entry] {
				diff.Removed = append(diff.Removed, TrustItem{Kind: "egress_allowlist", Value: entry})
			}
		}
		for _, host := range sortedUnique(snap.WebHosts) {
			if !curWebHosts[host] {
				diff.Removed = append(diff.Removed, TrustItem{Kind: "web_hosts", Value: host})
			}
		}
		for _, ruleID := range sortedUnique(snap.Waive) {
			if !curWaive[ruleID] {
				diff.Removed = append(diff.Removed, TrustItem{Kind: "waive", Value: ruleID})
			}
		}
		for _, glob := range sortedUnique(snap.SecretAllow) {
			if !curSecret[glob] {
				diff.Removed = append(diff.Removed, TrustItem{Kind: "secret_allow", Value: glob})
			}
		}
		if snap.AuditLog != "" && snap.AuditLog != curAudit {
			diff.Removed = append(diff.Removed, TrustItem{Kind: "audit_log", Value: snap.AuditLog})
		}
	}
	return diff
}
