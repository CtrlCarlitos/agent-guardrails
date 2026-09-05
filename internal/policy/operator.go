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
	Waive           []string `toml:"waive"`
	SecretAllow     bool     `toml:"secret_allow"`
	AuditLog        bool     `toml:"audit_log"`
	EgressAllowlist []string `toml:"egress_allowlist"`
}

// OperatorConfig is machine-scoped authorization living outside any repo.
// Grants are keyed by absolute repo path and never transfer between repos.
type OperatorConfig struct {
	Repos map[string]RepoGrant
}

func OperatorConfigPath() string {
	path, _ := operatorConfigPath(runtime.GOOS)
	return path
}

func operatorConfigPath(goos string) (string, error) {
	var base string
	if goos == "windows" {
		base = os.Getenv("APPDATA")
		if base == "" || !filepath.IsAbs(base) {
			return "", fmt.Errorf("APPDATA must be an absolute path")
		}
	} else if base = os.Getenv("XDG_CONFIG_HOME"); base != "" {
		if !filepath.IsAbs(base) {
			return "", fmt.Errorf("XDG_CONFIG_HOME must be an absolute path")
		}
	} else {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", fmt.Errorf("home directory is unavailable or not absolute")
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "guardrail", "waivers.toml"), nil
}

func emptyOperatorConfig() *OperatorConfig {
	return &OperatorConfig{Repos: map[string]RepoGrant{}}
}

func LoadOperatorConfig() (*OperatorConfig, error) {
	path, err := operatorConfigPath(runtime.GOOS)
	if err != nil {
		return emptyOperatorConfig(), fmt.Errorf("resolving operator config path: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyOperatorConfig(), nil
		}
		return emptyOperatorConfig(), fmt.Errorf("reading operator config %s: %w", path, err)
	}

	var repos map[string]RepoGrant
	if err := toml.Unmarshal(raw, &repos); err != nil {
		return emptyOperatorConfig(), fmt.Errorf("parsing operator config %s: %w", path, err)
	}
	normalized := make(map[string]RepoGrant, len(repos))
	rawPaths := make(map[string]string, len(repos))
	for repo, grant := range repos {
		if !filepath.IsAbs(repo) {
			return emptyOperatorConfig(), fmt.Errorf("operator config repository path %q must be absolute", repo)
		}
		cleaned := filepath.Clean(repo)
		if previous, ok := rawPaths[cleaned]; ok {
			return emptyOperatorConfig(), fmt.Errorf("operator config repository paths %q and %q have the same cleaned path", previous, repo)
		}
		rawPaths[cleaned] = repo
		normalized[cleaned] = grant
	}
	return &OperatorConfig{Repos: normalized}, nil
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

func (o *OperatorConfig) AllowsEgress(repoRoot, entry string) bool {
	grant, ok := o.grant(repoRoot)
	return ok && slices.Contains(grant.EgressAllowlist, entry)
}
