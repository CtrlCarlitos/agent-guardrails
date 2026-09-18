// Package coverage inventories a plane's runtime tool surface from its
// installed binary and diffs it against the plane contract, so an
// uncontracted tool — allow-by-default under the audit posture — surfaces
// at doctor time rather than in a hand audit.
package coverage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Inventory is what the scan of one Claude Code bundle established.
type Inventory struct {
	Version      string            // "2.1.275" when the bundle carries a version line
	Runtime      []string          // every tool name seen in a tool list or as an alias target, sorted
	Uncontracted []string          // Runtime names the contract does not know, sorted
	Aliases      map[string]string // legacy name → current name, from the bundle's alias map
	lists        int
	data         []byte // the scanned bundle, for stale-entry lookups
}

// Lists reports how many tool-name lists anchored the inventory.
func (inv Inventory) Lists() int { return inv.lists }

// Stale returns contracted names the bundle never mentions as a quoted
// string — entries the runtime may have retired.
func (inv Inventory) Stale(contracted []string) []string {
	var stale []string
	for _, name := range contracted {
		if !bytes.Contains(inv.data, []byte(`"`+name+`"`)) {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	return stale
}

var versionLine = regexp.MustCompile(`// Version: (\d+\.\d+\.\d+)`)

// quoted is one "Identifier" token: an uppercase-led run of 3–41 letters.
type quoted struct {
	start, end int // byte offsets of the opening and closing quote
	name       string
}

func isLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }
func isUpper(b byte) bool  { return b >= 'A' && b <= 'Z' }
func isWordByte(b byte) bool {
	return isLetter(b) || b >= '0' && b <= '9' || b == '_' || b == '$'
}

// quotedIdentifiers tokenizes every "Identifier" in one linear pass; a
// minified bundle is one 200 MB line, so this is the only affordable shape.
func quotedIdentifiers(data []byte) []quoted {
	var out []quoted
	for i := 0; i+4 < len(data); i++ {
		if data[i] != '"' || !isUpper(data[i+1]) {
			continue
		}
		j := i + 1
		for j < len(data) && isLetter(data[j]) {
			j++
		}
		n := j - (i + 1)
		if j < len(data) && data[j] == '"' && n >= 3 && n <= 41 {
			out = append(out, quoted{start: i, end: j, name: string(data[i+1 : j])})
			i = j
		}
	}
	return out
}

// separatedByComma reports whether only optional whitespace and one comma
// lie between two tokens — the JS list separator.
func separatedByComma(data []byte, from, to int) bool {
	comma := false
	for k := from + 1; k < to; k++ {
		switch data[k] {
		case ',':
			if comma {
				return false
			}
			comma = true
		case ' ', '\t', '\n', '\r':
		default:
			return false
		}
	}
	return comma
}

// aliasKey returns the Key of a Key:"Value" pair ending at the token, and
// where that key starts, when the token is such a pair.
func aliasKey(data []byte, q quoted) (string, int, bool) {
	i := q.start - 1
	if i < 0 || data[i] != ':' {
		return "", 0, false
	}
	j := i
	for j > 0 && isLetter(data[j-1]) {
		j--
	}
	n := i - j
	if n < 3 || n > 41 || !isUpper(data[j]) || (j > 0 && isWordByte(data[j-1])) {
		return "", 0, false
	}
	return string(data[j:i]), j, true
}

// ScanClaudeBundle reads a Claude Code bundle and anchors on two structures
// a minified build keeps intact: lists of quoted tool names, and the map
// that normalizes legacy tool names to current ones. A list counts only
// when at least half its members are already contracted — that is what
// separates tool lists from HTML element or exception-name lists — and the
// rest of such a list are the runtime's uncontracted tools.
func ScanClaudeBundle(r io.Reader, contracted func(string) bool) (Inventory, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Inventory{}, err
	}
	inv := Inventory{Aliases: map[string]string{}, data: data}
	if m := versionLine.FindSubmatch(data); m != nil {
		inv.Version = string(m[1])
	}
	tokens := quotedIdentifiers(data)
	runtime := map[string]bool{}

	// Tool lists: maximal runs of comma-separated quoted identifiers.
	for i := 0; i < len(tokens); {
		j := i + 1
		for j < len(tokens) && separatedByComma(data, tokens[j-1].end, tokens[j].start) {
			j++
		}
		if j-i >= 3 {
			known := 0
			for _, q := range tokens[i:j] {
				if contracted(q.name) {
					known++
				}
			}
			if known*2 >= j-i {
				inv.lists++
				for _, q := range tokens[i:j] {
					runtime[q.name] = true
				}
			}
		}
		i = j
	}

	// Alias map: maximal runs of Key:"Value" pairs joined by commas.
	type pair struct{ key, value string }
	for i := 0; i < len(tokens); {
		key, _, ok := aliasKey(data, tokens[i])
		if !ok {
			i++
			continue
		}
		run := []pair{{key, tokens[i].name}}
		j := i + 1
		for j < len(tokens) {
			nextKey, nextStart, ok := aliasKey(data, tokens[j])
			if !ok || nextStart != tokens[j-1].end+2 || data[tokens[j-1].end+1] != ',' {
				break
			}
			run = append(run, pair{nextKey, tokens[j].name})
			j++
		}
		if len(run) >= 3 {
			known := 0
			for _, p := range run {
				if contracted(p.value) || runtime[p.value] {
					known++
				}
			}
			if known*2 >= len(run) {
				for _, p := range run {
					inv.Aliases[p.key] = p.value
					runtime[p.value] = true
				}
			}
		}
		i = j
	}

	for name := range runtime {
		inv.Runtime = append(inv.Runtime, name)
		if !contracted(name) {
			inv.Uncontracted = append(inv.Uncontracted, name)
		}
	}
	sort.Strings(inv.Runtime)
	sort.Strings(inv.Uncontracted)
	return inv, nil
}

// ClaudeBundlePath locates the installed Claude Code bundle. The `claude`
// on PATH is the bundle itself on Unix (a symlink to the versioned build);
// on Windows the native installer leaves a launcher there and an npm-global
// install leaves a claude.cmd shim, neither of which carries the tool
// lists. A PATH entry without a version marker therefore falls back to the
// installer's versions directory — $XDG_DATA_HOME or ~/.local/share, then
// claude/versions — and takes its newest bundle.
func ClaudeBundlePath() (string, error) {
	var candidate string
	if bin, err := exec.LookPath("claude"); err == nil {
		if real, err := filepath.EvalSymlinks(bin); err == nil {
			candidate = real
		} else {
			candidate = bin
		}
		if _, err := ClaudeBundleVersion(candidate); err == nil {
			return candidate, nil
		}
	}
	versions, err := claudeVersionsDir()
	if err == nil {
		if newest, ok := newestVersionedBundle(versions); ok {
			return newest, nil
		}
	}
	if candidate == "" {
		return "", fmt.Errorf("claude is not on PATH and no bundle under %s", versions)
	}
	return "", fmt.Errorf("%s carries no Claude Code version marker (a launcher or shim) and no bundle under %s", candidate, versions)
}

// claudeVersionsDir is the native installer's versions directory on every
// platform: $XDG_DATA_HOME/claude/versions, else ~/.local/share/claude/versions.
func claudeVersionsDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "claude", "versions"), nil
}

// newestVersionedBundle picks the entry with the highest semantic version
// name that carries a version marker; installers keep several builds and
// the launcher points at the newest.
func newestVersionedBundle(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	var best string
	var bestKey []int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		key, ok := versionKey(strings.TrimSuffix(entry.Name(), ".exe"))
		if !ok {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if _, err := ClaudeBundleVersion(path); err != nil {
			continue
		}
		if best == "" || compareVersionKeys(key, bestKey) > 0 {
			best, bestKey = path, key
		}
	}
	return best, best != ""
}

func versionKey(name string) ([]int, bool) {
	parts := strings.Split(name, ".")
	if len(parts) < 3 {
		return nil, false
	}
	key := make([]int, 0, len(parts))
	for _, part := range parts {
		n := 0
		if part == "" {
			return nil, false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return nil, false
			}
			n = n*10 + int(r-'0')
		}
		key = append(key, n)
	}
	return key, true
}

func compareVersionKeys(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return 1
			}
			return -1
		}
	}
	return len(a) - len(b)
}

// Describe renders the inventory as doctor lines.
func (inv Inventory) Describe(contracted []string) []string {
	lines := []string{fmt.Sprintf("  runtime tools: %d (from %d tool lists, %d legacy aliases)", len(inv.Runtime), inv.lists, len(inv.Aliases))}
	if len(inv.Uncontracted) == 0 {
		lines = append(lines, "  uncontracted (allow-by-default): none")
	} else {
		lines = append(lines, "  uncontracted (allow-by-default): "+strings.Join(inv.Uncontracted, ", "))
	}
	if len(inv.Aliases) > 0 {
		keys := make([]string, 0, len(inv.Aliases))
		for k := range inv.Aliases {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]string, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, k+"→"+inv.Aliases[k])
		}
		lines = append(lines, "  legacy aliases: "+strings.Join(pairs, ", "))
	}
	if stale := inv.Stale(contracted); len(stale) > 0 {
		lines = append(lines, "  contracted but absent from the bundle: "+strings.Join(stale, ", "))
	}
	return lines
}

// versionMarker precedes the version in a Claude Code build. The bundle is
// a compiled executable with the JavaScript embedded deep inside it, so the
// marker is found by streaming, never by reading a header.
var versionMarker = []byte("// Version: ")

// ClaudeBundleVersion reads the bundle's version by streaming for the
// marker with a bounded buffer: an order of magnitude cheaper than the
// tool scan, and the only cost a cached session pays.
func ClaudeBundleVersion(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const chunk = 4 << 20
	overlap := len(versionMarker) + 32
	buf := make([]byte, chunk+overlap)
	carry := 0
	for {
		n, err := f.Read(buf[carry:])
		if n > 0 {
			window := buf[:carry+n]
			if i := bytes.Index(window, versionMarker); i >= 0 {
				if m := versionLine.FindSubmatch(window[i:]); m != nil {
					return string(m[1]), nil
				}
			}
			if len(window) > overlap {
				carry = copy(buf, window[len(window)-overlap:])
			} else {
				carry = len(window)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("no version line in the claude bundle")
			}
			return "", err
		}
	}
}

// Drift is the session-start view of one plane's coverage: the runtime
// version and what it exposes that the contract does not know.
type Drift struct {
	Version      string   `json:"version"`
	Guardrail    string   `json:"guardrail"` // contract provenance: a different release rescans
	Uncontracted []string `json:"uncontracted"`
	FromCache    bool     `json:"-"`
}

// ClaudeDrift answers "does the installed Claude Code expose tools the
// contract does not know" for the given guardrail release, scanning the
// bundle once per (bundle version, guardrail version) and caching the
// answer. Errors mean the question could not be answered (no bundle, no
// version); callers decide whether that is fatal — a session-start posture
// fails open, doctor fails loud.
func ClaudeDrift(contracted func(string) bool, guardrailVersion string) (Drift, error) {
	bundle, err := ClaudeBundlePath()
	if err != nil {
		return Drift{}, err
	}
	version, err := ClaudeBundleVersion(bundle)
	if err != nil {
		return Drift{}, err
	}
	var d Drift
	if LoadCached("claude", version, &d) && d.Version == version && d.Guardrail == guardrailVersion {
		d.FromCache = true
		return d, nil
	}
	f, err := os.Open(bundle)
	if err != nil {
		return Drift{}, err
	}
	defer f.Close()
	inv, err := ScanClaudeBundle(f, contracted)
	if err != nil {
		return Drift{}, err
	}
	d = Drift{Version: version, Guardrail: guardrailVersion, Uncontracted: inv.Uncontracted}
	if d.Uncontracted == nil {
		d.Uncontracted = []string{}
	}
	// A failed cache write only costs the next session a rescan.
	_ = StoreCached("claude", version, d)
	return d, nil
}
