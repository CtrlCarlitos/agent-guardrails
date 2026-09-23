package policy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"
)

const maxOverlayBytes = 1 << 20

type Overlay struct {
	EngineMinVersion   string
	AuditLog           string
	UnknownToolPosture UnknownToolPosture
	SafeRoots          []string
	SecretDirs         []string
	SecretGlobs        []string
	SecretAskGlobs     []string
	SecretAllow        []string
	EgressAllowlist    []string
	WebHosts           []string
	Recipes            RecipeConfig
	Rules              []Rule
	Waive              []string
	Path               string
}

func FindOverlayPath(cwd string) (path string, ok bool, warn string) {
	if v := os.Getenv("GUARDRAIL_CONFIG"); v != "" {
		if _, err := os.Stat(v); err != nil {
			return "", false, fmt.Sprintf("guardrail: GUARDRAIL_CONFIG is set to %s but that file does not exist; using base policy only", v)
		}
		return v, true, ""
	}
	root, ok := FindRepoRoot(cwd)
	if !ok {
		return "", false, ""
	}
	cfg := filepath.Join(root, "guardrail.toml")
	if _, err := os.Stat(cfg); err != nil {
		return "", false, ""
	}
	return cfg, true, ""
}

func FindRepoRoot(cwd string) (string, bool) {
	return findRepoRootWithCeilings(cwd, systemTempRoots())
}

// findRepoRootWithCeilings resolves the repository enclosing cwd. Discovery
// ceilings stop git's upward walk at the System temp root boundary so a stray
// repository at the root itself cannot capture resolution for strict
// descendants (the /tmp/.git lesson).
func findRepoRootWithCeilings(cwd string, ceilings []string) (string, bool) {
	if cwd == "" {
		return "", false
	}
	cmd := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel")
	if len(ceilings) > 0 {
		cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+strings.Join(ceilings, string(os.PathListSeparator)))
	}
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	root := strings.TrimSpace(string(out))
	return root, root != ""
}

// systemTempRoots mirrors the engine's System temp root set: the platform
// temp dir plus the Unix conventional roots, filtered to existing absolute
// directories that are not filesystem roots themselves.
func systemTempRoots() []string {
	candidates := []string{os.TempDir()}
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "/tmp", "/var/tmp")
	}
	seen := make(map[string]bool, len(candidates))
	roots := make([]string, 0, len(candidates))
	for _, root := range candidates {
		root = filepath.Clean(root)
		volumeRoot := filepath.VolumeName(root) + string(filepath.Separator)
		if !filepath.IsAbs(root) || root == volumeRoot || seen[root] {
			continue
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		seen[root] = true
		roots = append(roots, root)
		// Darwin: /tmp is a symlink to /private/tmp, so paths resolved for
		// policy no longer string-match the literal root. Carry the resolved
		// form too; containment then matches either spelling.
		if resolved, err := filepath.EvalSymlinks(root); err == nil && resolved != root && !seen[resolved] {
			seen[resolved] = true
			roots = append(roots, resolved)
		}
	}
	return roots
}

func LoadOverlay(pth string) (*Overlay, error) {
	if fi, err := os.Stat(pth); err == nil && fi.Size() > maxOverlayBytes {
		return nil, fmt.Errorf("overlay %s is %d bytes, over the %d limit; refusing to parse",
			pth, fi.Size(), maxOverlayBytes)
	}
	overlayFile, err := os.Open(pth)
	if err != nil {
		return nil, fmt.Errorf("reading overlay %s: %w", pth, err)
	}
	defer overlayFile.Close()
	raw, err := io.ReadAll(io.LimitReader(overlayFile, maxOverlayBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading overlay %s: %w", pth, err)
	}
	if len(raw) > maxOverlayBytes {
		return nil, fmt.Errorf("overlay %s is over the %d limit; refusing to parse", pth, maxOverlayBytes)
	}
	var f struct {
		EngineMinVersion   string   `toml:"engine_min_version"`
		AuditLog           string   `toml:"audit_log"`
		UnknownToolPosture string   `toml:"unknown_tool_posture"`
		Waive              []string `toml:"waive"`
		Slots              struct {
			SafeRoots       []string `toml:"safe_roots"`
			SecretDirs      []string `toml:"secret_dirs"`
			SecretGlobs     []string `toml:"secret_globs"`
			SecretAskGlobs  []string `toml:"secret_ask_globs"`
			SecretAllow     []string `toml:"secret_allow"`
			EgressAllowlist []string `toml:"egress_allowlist"`
			WebHosts        []string `toml:"web_hosts"`
		} `toml:"slots"`
		Recipes struct {
			Odoo *struct {
				Module       string `toml:"module"`
				TestDatabase string `toml:"test_database"`
				RelaxNG      string `toml:"relax_ng"`
			} `toml:"odoo"`
		} `toml:"recipes"`
		Rules []struct {
			ID       string   `toml:"id"`
			Tool     string   `toml:"tool"`
			Pattern  string   `toml:"pattern"`
			Decision string   `toml:"decision"`
			Reason   string   `toml:"reason"`
			Waive    []string `toml:"waive"`
		} `toml:"rules"`
	}
	metadata, err := toml.Decode(string(raw), &f)
	if err != nil {
		return nil, fmt.Errorf("parsing overlay %s: %w", pth, err)
	}
	for _, key := range metadata.Undecoded() {
		if len(key) > 0 && key[0] == "recipes" {
			return nil, fmt.Errorf("parsing overlay %s: unsupported recipe setting %s", pth, key.String())
		}
	}
	var unknownToolPosture UnknownToolPosture
	if f.UnknownToolPosture != "" {
		unknownToolPosture, err = ParseUnknownToolPosture(f.UnknownToolPosture)
		if err != nil {
			return nil, fmt.Errorf("parsing overlay %s: %w", pth, err)
		}
	}
	ov := &Overlay{
		EngineMinVersion:   f.EngineMinVersion,
		AuditLog:           f.AuditLog,
		UnknownToolPosture: unknownToolPosture,
		SafeRoots:          f.Slots.SafeRoots,
		SecretDirs:         f.Slots.SecretDirs,
		SecretGlobs:        f.Slots.SecretGlobs,
		SecretAskGlobs:     f.Slots.SecretAskGlobs,
		SecretAllow:        f.Slots.SecretAllow,
		EgressAllowlist:    f.Slots.EgressAllowlist,
		WebHosts:           f.Slots.WebHosts,
		Waive:              f.Waive,
		Path:               pth,
	}
	if f.Recipes.Odoo != nil {
		odoo := OdooRecipeConfig{
			Module:       f.Recipes.Odoo.Module,
			TestDatabase: f.Recipes.Odoo.TestDatabase,
			RelaxNG:      f.Recipes.Odoo.RelaxNG,
		}
		if err := validateOdooRecipeConfig(odoo); err != nil {
			return nil, fmt.Errorf("parsing overlay %s: %w", pth, err)
		}
		ov.Recipes.Odoo = &odoo
	}
	for _, r := range f.Rules {
		ov.Rules = append(ov.Rules, Rule{
			ID: r.ID, Tool: r.Tool, Pattern: r.Pattern,
			Decision: Decision(r.Decision), Reason: r.Reason,
		})
		ov.Waive = append(ov.Waive, r.Waive...)
	}
	return ov, nil
}

func validateOdooRecipeConfig(config OdooRecipeConfig) error {
	for _, field := range []struct{ name, value string }{
		{"module", config.Module},
		{"test_database", config.TestDatabase},
	} {
		name, value := field.name, field.value
		if value == "" {
			return fmt.Errorf("recipes.odoo.%s is required; unresolved recipe values fail closed", name)
		}
		for _, r := range value {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return fmt.Errorf("recipes.odoo.%s must be a literal command argument", name)
			}
		}
	}
	if config.RelaxNG == "" {
		return fmt.Errorf("recipes.odoo.relax_ng is required; unresolved recipe values fail closed")
	}
	clean := filepath.Clean(config.RelaxNG)
	forwardSlashClean := path.Clean(strings.ReplaceAll(config.RelaxNG, "\\", "/"))
	if filepath.IsAbs(config.RelaxNG) || filepath.VolumeName(config.RelaxNG) != "" ||
		looksLikeWindowsDrivePath(config.RelaxNG) ||
		strings.HasPrefix(config.RelaxNG, "/") || strings.HasPrefix(config.RelaxNG, "\\") ||
		clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		forwardSlashClean == ".." || strings.HasPrefix(forwardSlashClean, "../") {
		return fmt.Errorf("recipes.odoo.relax_ng must be a repository-relative file path")
	}
	if strings.ContainsAny(config.RelaxNG, "$%*?{}") {
		return fmt.Errorf("recipes.odoo.relax_ng must be a literal repository-relative path")
	}
	return nil
}

func looksLikeWindowsDrivePath(value string) bool {
	if len(value) < 2 || value[1] != ':' {
		return false
	}
	drive := value[0]
	return drive >= 'a' && drive <= 'z' || drive >= 'A' && drive <= 'Z'
}
