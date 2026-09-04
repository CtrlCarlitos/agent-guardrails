package policy

import (
	"fmt"
	"strconv"
	"strings"
)

func Merge(base *Policy, ov *Overlay, binaryVersion string) (*Policy, []string, error) {
	m := &Policy{
		Slots: Slots{
			SafeRoots:       append(append([]string{}, base.Slots.SafeRoots...), overlaySafe(ov)...),
			SecretGlobs:     append(append([]string{}, base.Slots.SecretGlobs...), overlayGlobs(ov)...),
			SecretAllow:     append(append([]string{}, base.Slots.SecretAllow...), overlayAllow(ov)...),
			EgressAllowlist: append(append([]string{}, base.Slots.EgressAllowlist...), overlayEgress(ov)...),
			AuditLog:        base.Slots.AuditLog,
		},
		Rules:  append([]Rule{}, base.Rules...),
		Waived: map[string]bool{},
	}
	for k, v := range base.Waived {
		m.Waived[k] = v
	}
	var warns []string
	if ov != nil {
		if ov.AuditLog != "" {
			m.Slots.AuditLog = ov.AuditLog
		}
		for _, r := range ov.Rules {
			if r.Decision != Ask && r.Decision != Deny {
				return nil, nil, fmt.Errorf("overlay rule %q uses decision %q; overlays may only add ask/deny (use slots or waive to loosen)", r.ID, r.Decision)
			}
			m.Rules = append(m.Rules, r)
		}
		for _, w := range ov.Waive {
			m.Waived[w] = true
			warns = append(warns, "guardrail: rule "+w+" is WAIVED by this repo's guardrail.toml")
		}
		if ov.EngineMinVersion != "" && versionOlder(binaryVersion, ov.EngineMinVersion) {
			warns = append(warns, fmt.Sprintf("guardrail: binary %s is older than this repo's engine_min_version %s", binaryVersion, ov.EngineMinVersion))
		}
	}
	return m, warns, nil
}

func overlaySafe(ov *Overlay) []string {
	if ov == nil {
		return nil
	}
	return ov.SafeRoots
}
func overlayGlobs(ov *Overlay) []string {
	if ov == nil {
		return nil
	}
	return ov.SecretGlobs
}
func overlayAllow(ov *Overlay) []string {
	if ov == nil {
		return nil
	}
	return ov.SecretAllow
}
func overlayEgress(ov *Overlay) []string {
	if ov == nil {
		return nil
	}
	return ov.EgressAllowlist
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
