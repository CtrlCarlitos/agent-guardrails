package engine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// core.hooksPath protection (#542).
//
// Git runs hooks from the directory core.hooksPath names. A global setting
// points every repository on the machine — including throwaway tmp-dir
// fixture repos a session creates — at ONE shared, real directory outside
// any repository (typically ~/.config/git/hooks). An agent writing a
// "fixture" hook there is planting code git will execute later from every
// repo, the same class as .git/hooks/**, so writes into the resolved
// directory deny under the same rule (P2.git-protected-path). Repo-local
// hooksPath values pointing outside that repository's own .git are covered
// too; relative values resolve against the repository root, as git resolves
// them at hook-execution time. A *relative* global hooksPath is
// repo-dependent by design and is not resolved here.
//
// The global resolution is parsed from git's own config files in-process
// (no `git config` spawn: hooks are latency-sensitive) and cached for the
// process lifetime; tests reset the cache.

var (
	hooksPathMu         sync.Mutex
	globalHooksPathcell *string // nil = not resolved yet; "" = unset
)

func resetGlobalHooksPathCache() {
	hooksPathMu.Lock()
	globalHooksPathcell = nil
	hooksPathMu.Unlock()
}

// resolveGlobalHooksPath returns the absolute directory the global git
// configuration resolves core.hooksPath to, if any.
func resolveGlobalHooksPath() (string, bool) {
	hooksPathMu.Lock()
	defer hooksPathMu.Unlock()
	if globalHooksPathcell != nil {
		return *globalHooksPathcell, *globalHooksPathcell != ""
	}
	resolved := ""
	for _, path := range globalGitConfigPaths() {
		if value, ok := scanGitConfigHooksPath(path); ok {
			resolved = expandHome(value)
		}
	}
	globalHooksPathcell = &resolved
	return resolved, resolved != ""
}

// globalGitConfigPaths lists git's global config files in precedence order
// (later entries override earlier ones).
func globalGitConfigPaths() []string {
	home, homeErr := os.UserHomeDir()
	var paths []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "git", "config"))
	} else if homeErr == nil {
		paths = append(paths, filepath.Join(home, ".config", "git", "config"))
	}
	if homeErr == nil {
		paths = append(paths, filepath.Join(home, ".gitconfig"))
	}
	return paths
}

// scanGitConfigHooksPath extracts the last core.hooksPath value from a git
// config file. Git config is INI-like; a strict two-line scanner (section
// headers, key = value) is enough here and cannot be confused by other
// sections. Section and key names are case-insensitive, as git treats them.
func scanGitConfigHooksPath(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	inCore, value, found := false, "", false
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end < 0 {
				inCore = false
				continue
			}
			section := strings.TrimSpace(line[1:end])
			if i := strings.IndexAny(section, " \t\""); i >= 0 {
				section = section[:i] // subsections are not [core]
			}
			inCore = strings.EqualFold(section, "core")
			continue
		}
		if !inCore {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(key), "hooksPath") {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
			val = val[1 : len(val)-1]
		}
		value, found = val, val != ""
	}
	return value, found
}

// repoHooksPathDir resolves the hooks directory for one repository: its own
// .git/config wins over the global setting, relative values resolve against
// the repository root, and the repository's .git/hooks default is already
// covered by gitProtectedGlobs. The result is absolute or empty.
func repoHooksPathDir(repoRoot string) string {
	if repoRoot == "" {
		return ""
	}
	value, ok := scanGitConfigHooksPath(filepath.Join(repoRoot, ".git", "config"))
	if !ok {
		return ""
	}
	expanded := expandHome(value)
	if !filepath.IsAbs(expanded) {
		expanded = filepath.Join(repoRoot, expanded)
	}
	return filepath.Clean(expanded)
}

func expandHome(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), "/"))
		}
	}
	return path
}

// candidateInsideHooksDir reports whether a write candidate lands inside dir.
func candidateInsideHooksDir(candidate pathCandidate, dir string) bool {
	if dir == "" {
		return false
	}
	p := strings.TrimPrefix(candidate.path, "./")
	p = expandHome(p)
	if !filepath.IsAbs(p) {
		if candidate.cwdUnknown || candidate.cwd == "" {
			return false
		}
		p = filepath.Join(candidate.cwd, p)
	}
	p = filepath.Clean(p)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// checkHooksPathCandidate denies writes into a core.hooksPath directory.
func checkHooksPathCandidate(candidate pathCandidate) *policy.Verdict {
	if dir, ok := resolveGlobalHooksPath(); ok && candidateInsideHooksDir(candidate, dir) {
		return hooksPathVerdict(dir)
	}
	if dir := repoHooksPathDir(candidate.repoRoot); dir != "" && candidateInsideHooksDir(candidate, dir) {
		return hooksPathVerdict(dir)
	}
	return nil
}

func hooksPathVerdict(dir string) *policy.Verdict {
	return &policy.Verdict{
		Decision: policy.Deny,
		RuleID:   "P2.git-protected-path",
		Reason:   "write to the git hooks directory core.hooksPath resolves to: " + dir,
	}
}
