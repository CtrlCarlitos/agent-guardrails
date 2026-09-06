package policy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

const maxOverlayBytes = 1 << 20

type Overlay struct {
	EngineMinVersion string
	AuditLog         string
	SafeRoots        []string
	SecretDirs       []string
	SecretGlobs      []string
	SecretAllow      []string
	EgressAllowlist  []string
	Rules            []Rule
	Waive            []string
	Path             string
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
	if cwd == "" {
		return "", false
	}
	out, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", false
	}
	root := strings.TrimSpace(string(out))
	return root, root != ""
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
		EngineMinVersion string   `toml:"engine_min_version"`
		AuditLog         string   `toml:"audit_log"`
		Waive            []string `toml:"waive"`
		Slots            struct {
			SafeRoots       []string `toml:"safe_roots"`
			SecretDirs      []string `toml:"secret_dirs"`
			SecretGlobs     []string `toml:"secret_globs"`
			SecretAllow     []string `toml:"secret_allow"`
			EgressAllowlist []string `toml:"egress_allowlist"`
		} `toml:"slots"`
		Rules []struct {
			ID       string   `toml:"id"`
			Tool     string   `toml:"tool"`
			Pattern  string   `toml:"pattern"`
			Decision string   `toml:"decision"`
			Reason   string   `toml:"reason"`
			Waive    []string `toml:"waive"`
		} `toml:"rules"`
	}
	if err := toml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing overlay %s: %w", pth, err)
	}
	ov := &Overlay{
		EngineMinVersion: f.EngineMinVersion,
		AuditLog:         f.AuditLog,
		SafeRoots:        f.Slots.SafeRoots,
		SecretDirs:       f.Slots.SecretDirs,
		SecretGlobs:      f.Slots.SecretGlobs,
		SecretAllow:      f.Slots.SecretAllow,
		EgressAllowlist:  f.Slots.EgressAllowlist,
		Waive:            f.Waive,
		Path:             pth,
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
