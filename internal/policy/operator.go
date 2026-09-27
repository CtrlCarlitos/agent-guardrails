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
	WebHosts        []string `toml:"web_hosts"`
	// Commands are operator-issued grants for one exact command each. A grant
	// is a third kind of entry in a structure that already has the right
	// ownership and the right scoping rule: this file is owner-only, and
	// grants keyed by absolute repo path never transfer between repos.
	Commands []CommandGrant `toml:"grant"`
}

// OperatorConfig is machine-scoped authorization living outside any repo.
// Grants are keyed by absolute repo path and never transfer between repos.
type OperatorConfig struct {
	GlobalWebHosts         []string
	WebResearchEnforcement string // empty is legacy/strict; only explicit "off" relaxes native research
	// Approval is the top-level `approval` key: how operator actions are
	// approved (ADR-0033). Empty means the default, ApprovalPrompt. Only
	// Operator config carries it; an Overlay has no such field.
	Approval string
	Repos    map[string]RepoGrant
}

// The two approval modes (ADR-0033). Prompt asks through the plane's native
// ask or a terminal [y/N]; passkey is the WebAuthn broker of ADR-0021/0025.
const (
	ApprovalPrompt  = "prompt"
	ApprovalPasskey = "passkey"
)

// ApprovalMode is the operator's chosen approval mode, ApprovalPrompt unless
// the file says `approval = "passkey"`. A nil config (none on disk) is the
// default. An unreadable config is the caller's to resolve: it must not reach
// here as a downgrade (the CLI and hook treat it as ApprovalPasskey).
func (o *OperatorConfig) ApprovalMode() string {
	if o != nil && o.Approval == ApprovalPasskey {
		return ApprovalPasskey
	}
	return ApprovalPrompt
}

// operatorTopLevelKeys are the Operator config keys that are not repository
// tables.
var operatorTopLevelKeys = map[string]bool{"web_hosts": true, "web_research": true, "approval": true}

func OperatorConfigPath() string {
	path, _ := operatorConfigPath(runtime.GOOS)
	return path
}

func OperatorConfigDir() (string, error) {
	return operatorConfigDir(runtime.GOOS)
}

func operatorConfigPath(goos string) (string, error) {
	base, err := operatorConfigDir(goos)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "waivers.toml"), nil
}

func operatorConfigDir(goos string) (string, error) {
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
	return filepath.Join(base, "guardrail"), nil
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

	var global struct {
		Approval    *string `toml:"approval"`
		WebResearch struct {
			Enforcement string `toml:"enforcement"`
		} `toml:"web_research"`
		WebHosts struct {
			Global []string `toml:"global"`
		} `toml:"web_hosts"`
	}
	if err := toml.Unmarshal(raw, &global); err != nil {
		return emptyOperatorConfig(), fmt.Errorf("parsing operator config %s: %w", path, err)
	}
	approval := ""
	if global.Approval != nil {
		approval = *global.Approval
		if approval != ApprovalPrompt && approval != ApprovalPasskey {
			return emptyOperatorConfig(), fmt.Errorf("invalid approval; want %q or %q", ApprovalPrompt, ApprovalPasskey)
		}
	}
	if mode := global.WebResearch.Enforcement; mode != "" && mode != "on" && mode != "off" {
		return emptyOperatorConfig(), fmt.Errorf("invalid web_research.enforcement; want on or off")
	}
	for _, host := range global.WebHosts.Global {
		if err := ValidateWebHost(host); err != nil {
			return emptyOperatorConfig(), err
		}
	}
	// Repository tables are every other top-level key. Decode each one on its
	// own so a top-level scalar such as `approval` is not read as a table.
	var top map[string]toml.Primitive
	metadata, err := toml.Decode(string(raw), &top)
	if err != nil {
		return emptyOperatorConfig(), fmt.Errorf("parsing operator config %s: %w", path, err)
	}
	repos := make(map[string]RepoGrant, len(top))
	for key, primitive := range top {
		if operatorTopLevelKeys[key] {
			continue
		}
		var grant RepoGrant
		if err := metadata.PrimitiveDecode(primitive, &grant); err != nil {
			return emptyOperatorConfig(), fmt.Errorf("parsing operator config %s: %w", path, err)
		}
		repos[key] = grant
	}
	normalized := make(map[string]RepoGrant, len(repos))
	rawPaths := make(map[string]string, len(repos))
	for repo, grant := range repos {
		if !filepath.IsAbs(repo) {
			return emptyOperatorConfig(), fmt.Errorf("operator config repository path %q must be absolute", repo)
		}
		for _, host := range grant.WebHosts {
			if err := ValidateWebHost(host); err != nil {
				return emptyOperatorConfig(), err
			}
		}
		cleaned := filepath.Clean(repo)
		if previous, ok := rawPaths[cleaned]; ok {
			return emptyOperatorConfig(), fmt.Errorf("operator config repository paths %q and %q have the same cleaned path", previous, repo)
		}
		rawPaths[cleaned] = repo
		normalized[cleaned] = grant
	}
	return &OperatorConfig{GlobalWebHosts: global.WebHosts.Global, WebResearchEnforcement: global.WebResearch.Enforcement, Approval: approval, Repos: normalized}, nil
}

func (o *OperatorConfig) grant(repoRoot string) (RepoGrant, bool) {
	if o == nil || o.Repos == nil || !filepath.IsAbs(repoRoot) {
		return RepoGrant{}, false
	}
	cleaned := filepath.Clean(repoRoot)
	if grant, ok := o.Repos[cleaned]; ok {
		return grant, true
	}
	// Darwin temp-symlink divergence: git reports the physical repo root
	// (/private/var/...) while grants may be keyed — or queried — by the
	// symlinked spelling (/var/folders/...). Resolve both sides before
	// declaring no grant.
	want := resolvePathForCompare(cleaned)
	for root, grant := range o.Repos {
		if resolvePathForCompare(filepath.Clean(root)) == want {
			return grant, true
		}
	}
	return RepoGrant{}, false
}

func resolvePathForCompare(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
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

func (o *OperatorConfig) AllowsGlobalWebHost(host string) bool {
	return o != nil && ValidateWebHost(host) == nil && slices.Contains(o.GlobalWebHosts, host)
}

func (o *OperatorConfig) AllowsWebHost(repoRoot, host string) bool {
	grant, ok := o.grant(repoRoot)
	return ok && ValidateWebHost(host) == nil && slices.Contains(grant.WebHosts, host)
}
