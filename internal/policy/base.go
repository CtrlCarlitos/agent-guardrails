package policy

import (
	_ "embed"

	"github.com/BurntSushi/toml"
)

//go:embed base.toml
var baseTOML []byte

type fileShape struct {
	Slots struct {
		SafeRoots       []string `toml:"safe_roots"`
		SecretGlobs     []string `toml:"secret_globs"`
		SecretAllow     []string `toml:"secret_allow"`
		EgressAllowlist []string `toml:"egress_allowlist"`
		AuditLog        string   `toml:"audit_log"`
	} `toml:"slots"`
	Rules []struct {
		ID       string `toml:"id"`
		Tool     string `toml:"tool"`
		Pattern  string `toml:"pattern"`
		Decision string `toml:"decision"`
		Reason   string `toml:"reason"`
	} `toml:"rules"`
}

func (f fileShape) toPolicy() *Policy {
	p := &Policy{
		Slots: Slots{
			SafeRoots:       f.Slots.SafeRoots,
			SecretGlobs:     f.Slots.SecretGlobs,
			SecretAllow:     f.Slots.SecretAllow,
			EgressAllowlist: f.Slots.EgressAllowlist,
			AuditLog:        f.Slots.AuditLog,
		},
		Waived: map[string]bool{},
	}
	for _, r := range f.Rules {
		p.Rules = append(p.Rules, Rule{
			ID: r.ID, Tool: r.Tool, Pattern: r.Pattern,
			Decision: Decision(r.Decision), Reason: r.Reason,
		})
	}
	return p
}

func LoadBase() (*Policy, error) {
	var f fileShape
	if err := toml.Unmarshal(baseTOML, &f); err != nil {
		return nil, err
	}
	return f.toPolicy(), nil
}
