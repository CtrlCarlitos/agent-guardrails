package recipe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Session checks are skipped when none of a recipe's files changed since they
// last passed (#481). The Go tier ran build, test, lint and vulncheck on
// every Claude Stop, several minutes in this repository, even after a turn
// that touched no Go file.
//
// A recipe's files are those with one of its extensions, its root markers
// and its SessionInputs. The fingerprint covers their blob ids at HEAD, the
// content of any of them that is modified, deleted or untracked, and the
// recipe's session commands. A pass records it; a failure never does, so a
// red repository keeps being checked. Without git, or on any git error, there
// is no fingerprint and the checks run as before.

// sessionFingerprint is a seam for tests.
var sessionFingerprint = gitSessionFingerprint

func gitSessionFingerprint(root string, r Recipe) (string, error) {
	if root == "" {
		return "", errors.New("no repository root")
	}
	tree, err := gitOutput(root, "ls-tree", "-r", "-z", "HEAD")
	if err != nil {
		return "", err
	}
	status, err := gitOutput(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	if err != nil {
		return "", err
	}
	var lines []string
	for _, entry := range bytes.Split(tree, []byte{0}) {
		// "<mode> <type> <object>\t<path>"
		meta, path, ok := strings.Cut(string(entry), "\t")
		if ok && r.sessionInput(path) {
			lines = append(lines, "tree "+path+" "+meta)
		}
	}
	entries := bytes.Split(status, []byte{0})
	for i := 0; i < len(entries); i++ {
		entry := string(entries[i])
		if len(entry) < 4 {
			continue
		}
		code, path := entry[:2], entry[3:]
		if code[0] == 'R' || code[0] == 'C' {
			i++ // a rename or copy is followed by its source path
		}
		if !r.sessionInput(path) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		switch {
		case err == nil:
			sum := sha256.Sum256(content)
			lines = append(lines, "work "+path+" "+hex.EncodeToString(sum[:]))
		case os.IsNotExist(err):
			lines = append(lines, "work "+path+" deleted")
		default:
			return "", err
		}
	}
	sort.Strings(lines)
	for _, command := range r.Session {
		lines = append(lines, "cmd "+strings.Join(command, "\x1f"))
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

func gitOutput(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	return cmd.Output()
}

// sessionInput reports whether a repository-relative path is one of the
// recipe's files.
func (r Recipe) sessionInput(path string) bool {
	base := filepath.Base(filepath.FromSlash(path))
	if recipeMatchesExtension(r, filepath.Ext(base)) {
		return true
	}
	for _, name := range append(append([]string{}, r.RootMarkers...), r.SessionInputs...) {
		if base == name {
			return true
		}
	}
	return false
}

func sessionPassPath(root string, r Recipe) (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	key := sha256.Sum256([]byte(filepath.Clean(root) + "\x00" + r.Name))
	return filepath.Join(base, "guardrail", "session-checks", hex.EncodeToString(key[:16])), nil
}

func sessionPassed(root string, r Recipe, fingerprint string) bool {
	path, err := sessionPassPath(root, r)
	if err != nil {
		return false
	}
	recorded, err := os.ReadFile(path)
	return err == nil && string(recorded) == fingerprint
}

func recordSessionPass(root string, r Recipe, fingerprint string) {
	path, err := sessionPassPath(root, r)
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = os.WriteFile(path, []byte(fingerprint), 0o600)
}
