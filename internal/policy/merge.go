package policy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
)

func Merge(base *Policy, ov *Overlay, binaryVersion string, op *OperatorConfig, repoRoot string) (*Policy, []string, error) {
	m := &Policy{
		Slots: Slots{
			SafeRoots:       append([]string{}, base.Slots.SafeRoots...),
			SecretGlobs:     append([]string{}, base.Slots.SecretGlobs...),
			SecretAllow:     append([]string{}, base.Slots.SecretAllow...),
			EgressAllowlist: append([]string{}, base.Slots.EgressAllowlist...),
			AuditLog:        base.Slots.AuditLog,
		},
		Rules:  append([]Rule{}, base.Rules...),
		Waived: map[string]bool{},
	}
	for k, v := range base.Waived {
		m.Waived[k] = v
	}
	var warns []string
	if ov == nil {
		return m, warns, nil
	}

	// These additions can only make the Base policy stricter.
	m.Slots.SecretGlobs = append(m.Slots.SecretGlobs, ov.SecretGlobs...)
	for _, r := range ov.Rules {
		if r.Decision != Ask && r.Decision != Deny {
			return nil, nil, fmt.Errorf("overlay rule %q uses decision %q; overlays may only add ask/deny (use slots or waive to loosen)", r.ID, r.Decision)
		}
		m.Rules = append(m.Rules, r)
	}

	cleanRoot := filepath.Clean(repoRoot)
	resolvedRoot, rootErr := pathutil.ResolveThroughExistingAncestor(cleanRoot)
	for _, sr := range ov.SafeRoots {
		rawCandidate := sr
		if !filepath.IsAbs(rawCandidate) {
			rawCandidate = cleanRoot + string(filepath.Separator) + rawCandidate
		}
		resolved, resolveErr := pathutil.ResolveThroughExistingAncestor(rawCandidate)

		candidate := sr
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(cleanRoot, candidate)
		}
		candidate = filepath.Clean(candidate)
		lexicalRel, lexicalErr := filepath.Rel(cleanRoot, candidate)
		resolvedRel, resolvedRelErr := filepath.Rel(resolvedRoot, resolved)
		if !filepath.IsAbs(repoRoot) || rootErr != nil || lexicalErr != nil || pathEscapesRoot(lexicalRel) ||
			resolveErr != nil || resolvedRelErr != nil || pathEscapesRoot(resolvedRel) {
			warns = append(warns, "guardrail: repo requested safe_root "+sr+" outside the repository — DROPPED")
			continue
		}
		m.Slots.SafeRoots = append(m.Slots.SafeRoots, candidate)
	}

	for _, entry := range ov.EgressAllowlist {
		if entry == "*" || entry == "**" {
			warns = append(warns, "guardrail: repo requested a wildcard egress_allowlist entry "+entry+" — DROPPED")
			continue
		}
		if !op.AllowsEgress(repoRoot, entry) {
			warns = append(warns, "guardrail: repo requested egress_allowlist entry "+entry+
				", which is NOT authorized in "+OperatorConfigPath()+" — DROPPED")
			continue
		}
		m.Slots.EgressAllowlist = append(m.Slots.EgressAllowlist, entry)
	}

	if len(ov.SecretAllow) > 0 {
		if op.AllowsSecretAllow(repoRoot) {
			m.Slots.SecretAllow = append(m.Slots.SecretAllow, ov.SecretAllow...)
		} else {
			warns = append(warns, "guardrail: repo requested secret_allow entries, which are NOT authorized in "+
				OperatorConfigPath()+" — secret protection remains ENFORCED")
		}
	}

	if ov.AuditLog != "" {
		if op.AllowsAuditLog(repoRoot) {
			m.Slots.AuditLog = ov.AuditLog
		} else {
			warns = append(warns, "guardrail: repo requested audit_log "+ov.AuditLog+
				", which is NOT authorized in "+OperatorConfigPath()+" — the default audit path is retained")
		}
	}

	for _, waiver := range ov.Waive {
		if neverWaivable[waiver] {
			warns = append(warns, "guardrail: rule "+waiver+" can never be waived (fail-closed backstop) — request IGNORED")
			continue
		}
		if op.AllowsWaiver(repoRoot, waiver) {
			m.Waived[waiver] = true
			warns = append(warns, "guardrail: rule "+waiver+" is WAIVED for this repo by operator authorization")
			continue
		}
		warns = append(warns, "guardrail: repo requested waiver of "+waiver+
			", which is NOT authorized in "+OperatorConfigPath()+" — the rule remains ENFORCED")
	}

	if ov.EngineMinVersion != "" && versionOlder(binaryVersion, ov.EngineMinVersion) {
		warns = append(warns, fmt.Sprintf("guardrail: binary %s is older than this repo's engine_min_version %s", binaryVersion, ov.EngineMinVersion))
	}
	return m, warns, nil
}

func pathEscapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func versionOlder(bin, min string) bool {
	bp, ok1 := parseVer(bin)
	mp, ok2 := parseVer(min)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if bp[i] != mp[i] {
			return bp[i] < mp[i]
		}
	}
	return false
}

func parseVer(s string) ([3]int, bool) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(strings.TrimRightFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
