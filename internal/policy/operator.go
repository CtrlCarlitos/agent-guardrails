package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/BurntSushi/toml"
)

// neverWaivable are the fail-closed backstops. Waiving one converts the
// engine's fail-closed design into a fail-open one, so no grant can switch it off.
var neverWaivable = map[string]bool{
	"tokenize-failed": true,
	"panic-recovered": true,
	"P3.unresolved":   true,
}

type RepoGrant struct {
	Waive       []string `toml:"waive"`
	SecretAllow bool     `toml:"secret_allow"`
	AuditLog    bool     `toml:"audit_log"`
}

// OperatorConfig is machine-scoped authorization living outside any repo.
// Grants are keyed by absolute repo path and never transfer between repos.
type OperatorConfig struct {
	Repos map[string]RepoGrant
}

func OperatorConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "guardrail", "waivers.toml")
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "guardrail", "waivers.toml")
}

func LoadOperatorConfig() (*OperatorConfig, error) {
	o := &OperatorConfig{Repos: map[string]RepoGrant{}}
	path := OperatorConfigPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return o, nil
		}
		return o, fmt.Errorf("reading operator config %s: %w", path, err)
	}

	var repos map[string]RepoGrant
	if err := toml.Unmarshal(raw, &repos); err != nil {
		return o, fmt.Errorf("parsing operator config %s: %w", path, err)
	}
	for repo, grant := range repos {
		if !filepath.IsAbs(repo) {
			return o, fmt.Errorf("operator config repository path %q must be absolute", repo)
		}
		o.Repos[filepath.Clean(repo)] = grant
	}
	return o, nil
}

func (o *OperatorConfig) grant(repoRoot string) (RepoGrant, bool) {
	if o == nil || o.Repos == nil || !filepath.IsAbs(repoRoot) {
		return RepoGrant{}, false
	}
	grant, ok := o.Repos[filepath.Clean(repoRoot)]
	return grant, ok
}

func (o *OperatorConfig) AllowsWaiver(repoRoot, ruleID string) bool {
	if neverWaivable[ruleID] {
		return false
	}
	grant, ok := o.grant(repoRoot)
	return ok && slices.Contains(grant.Waive, ruleID)
}

func (o *OperatorConfig) AllowsSecretAllow(repoRoot string) bool {
	grant, ok := o.grant(repoRoot)
	return ok && grant.SecretAllow
}

func (o *OperatorConfig) AllowsAuditLog(repoRoot string) bool {
	grant, ok := o.grant(repoRoot)
	return ok && grant.AuditLog
}
