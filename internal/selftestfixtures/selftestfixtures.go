// Package selftestfixtures owns the embedded hook-payload fixtures shared by
// `guardrail selftest` and the contract test suite (#107).
package selftestfixtures

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
)

// FS holds the embedded fixture tree under fixtures/<plane>/.
//
//go:embed all:fixtures
var FS embed.FS

// Probe is one direct hook invocation with its expected verdict.
type Probe struct {
	Plane        string
	File         string
	Name         string
	Args         []string
	Payload      string
	WantDecision string
	WantRuleID   string
}

type expectation struct {
	Name     string `json:"name,omitempty"`
	Decision string `json:"decision"`
	Rule     string `json:"rule,omitempty"`
}

const tempDirPlaceholder = `"__TEMPDIR__"`

var canonicalPlaneOrder = []string{"claude", "opencode", "antigravity", "codex"}

// Load returns the complete selftest probe matrix for goos (e.g., runtime.GOOS).
// Base fixtures under fixtures/<plane>/ load on every OS; fixtures under
// fixtures/<plane>/<goos>/ override matching filenames and append OS-specific
// probes when goos matches.
func Load(goos string) ([]Probe, error) {
	return LoadFromFS(FS, goos)
}

// LoadPlatformVariants returns only the OS-specific fixtures under
// fixtures/<plane>/<goos>/ across all planes. Used by tests that inspect or
// execute a specific platform's variant probes directly.
func LoadPlatformVariants(goos string) ([]Probe, error) {
	return LoadPlatformVariantsFromFS(FS, goos)
}

// LoadFromFS loads the selftest probe matrix for goos from an arbitrary fs.FS
// rooted above a "fixtures" directory.
func LoadFromFS(fsys fs.FS, goos string) ([]Probe, error) {
	planes, err := listPlanes(fsys)
	if err != nil {
		return nil, err
	}
	if len(planes) == 0 {
		return nil, fmt.Errorf("selftestfixtures: no plane directories found under fixtures/")
	}

	var all []Probe
	for _, plane := range planes {
		args, err := hookArgsForPlane(plane)
		if err != nil {
			return nil, err
		}
		baseDir := path.Join("fixtures", plane)
		baseProbes, err := loadDir(fsys, baseDir, plane, args)
		if err != nil {
			return nil, err
		}
		if len(baseProbes) == 0 {
			return nil, fmt.Errorf("selftestfixtures: plane %q has zero probes", plane)
		}

		// Validate any platform variant directories present even when not
		// selected for goos, and apply the variant matching goos.
		entries, err := fs.ReadDir(fsys, baseDir)
		if err != nil {
			return nil, fmt.Errorf("selftestfixtures: read %s: %w", baseDir, err)
		}
		var variantDirs []string
		for _, e := range entries {
			if e.IsDir() {
				variantDirs = append(variantDirs, e.Name())
			}
		}
		sort.Strings(variantDirs)

		merged := append([]Probe(nil), baseProbes...)
		indexByFile := make(map[string]int, len(merged))
		for i, p := range merged {
			indexByFile[p.File] = i
		}

		for _, vOS := range variantDirs {
			vDir := path.Join(baseDir, vOS)
			vProbes, err := loadDir(fsys, vDir, plane, args)
			if err != nil {
				return nil, err
			}
			if len(vProbes) == 0 {
				return nil, fmt.Errorf("selftestfixtures: variant directory %s has zero probes", vDir)
			}
			if vOS != goos {
				continue
			}
			for _, vp := range vProbes {
				if idx, exists := indexByFile[vp.File]; exists {
					merged[idx] = vp
				} else {
					indexByFile[vp.File] = len(merged)
					merged = append(merged, vp)
				}
			}
		}

		all = append(all, merged...)
	}

	return all, nil
}

// LoadPlatformVariantsFromFS returns only the probes declared inside
// fixtures/<plane>/<goos>/ directories.
func LoadPlatformVariantsFromFS(fsys fs.FS, goos string) ([]Probe, error) {
	planes, err := listPlanes(fsys)
	if err != nil {
		return nil, err
	}
	var out []Probe
	for _, plane := range planes {
		args, err := hookArgsForPlane(plane)
		if err != nil {
			return nil, err
		}
		vDir := path.Join("fixtures", plane, goos)
		if _, err := fs.Stat(fsys, vDir); err != nil {
			continue
		}
		vProbes, err := loadDir(fsys, vDir, plane, args)
		if err != nil {
			return nil, err
		}
		out = append(out, vProbes...)
	}
	return out, nil
}

func listPlanes(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, "fixtures")
	if err != nil {
		return nil, fmt.Errorf("selftestfixtures: read fixtures/: %w", err)
	}
	present := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			present[e.Name()] = true
		}
	}
	var planes []string
	for _, p := range canonicalPlaneOrder {
		if present[p] {
			planes = append(planes, p)
			delete(present, p)
		}
	}
	var extra []string
	for p := range present {
		extra = append(extra, p)
	}
	sort.Strings(extra)
	planes = append(planes, extra...)
	return planes, nil
}

func hookArgsForPlane(plane string) ([]string, error) {
	switch plane {
	case "claude", "opencode", "codex":
		return []string{plane}, nil
	case "antigravity":
		return []string{"antigravity", "pre"}, nil
	default:
		return nil, fmt.Errorf("selftestfixtures: unknown plane %q", plane)
	}
}

func loadDir(fsys fs.FS, dir, plane string, args []string) ([]Probe, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("selftestfixtures: read %s: %w", dir, err)
	}
	expPath := path.Join(dir, "expected.json")
	expRaw, err := fs.ReadFile(fsys, expPath)
	if err != nil {
		return nil, fmt.Errorf("selftestfixtures: missing %s: %w", expPath, err)
	}
	var expected map[string]expectation
	if err := json.Unmarshal(expRaw, &expected); err != nil {
		return nil, fmt.Errorf("selftestfixtures: parse %s: %w", expPath, err)
	}
	if len(expected) == 0 {
		return nil, fmt.Errorf("selftestfixtures: %s defines zero expectations", expPath)
	}

	payloadFiles := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "expected.json" || !strings.HasSuffix(name, ".json") {
			continue
		}
		payloadFiles[name] = true
	}

	// Reject orphan payload files not listed in expected.json.
	var orphans []string
	for f := range payloadFiles {
		if _, ok := expected[f]; !ok {
			orphans = append(orphans, path.Join(dir, f))
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		return nil, fmt.Errorf("selftestfixtures: payload file(s) missing from %s: %s", expPath, strings.Join(orphans, ", "))
	}

	// Reject expectations pointing at missing payload files.
	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	probes := make([]Probe, 0, len(keys))
	for _, file := range keys {
		exp := expected[file]
		if !payloadFiles[file] {
			return nil, fmt.Errorf("selftestfixtures: %s references missing payload %s", expPath, path.Join(dir, file))
		}
		if strings.TrimSpace(exp.Decision) == "" {
			return nil, fmt.Errorf("selftestfixtures: %s entry %q has empty decision", expPath, file)
		}
		pPath := path.Join(dir, file)
		raw, err := fs.ReadFile(fsys, pPath)
		if err != nil {
			return nil, fmt.Errorf("selftestfixtures: read %s: %w", pPath, err)
		}
		payload := strings.TrimSpace(string(raw))
		if strings.Contains(payload, tempDirPlaceholder) {
			encodedTemp, err := json.Marshal(os.TempDir())
			if err != nil {
				return nil, fmt.Errorf("selftestfixtures: encode TempDir: %w", err)
			}
			payload = strings.ReplaceAll(payload, tempDirPlaceholder, string(encodedTemp))
		}
		if !json.Valid([]byte(payload)) {
			return nil, fmt.Errorf("selftestfixtures: %s is not valid JSON", pPath)
		}
		name := exp.Name
		if name == "" {
			name = strings.TrimSuffix(file, ".json")
		}
		probes = append(probes, Probe{
			Plane:        plane,
			File:         file,
			Name:         name,
			Args:         append([]string(nil), args...),
			Payload:      payload,
			WantDecision: exp.Decision,
			WantRuleID:   exp.Rule,
		})
	}
	return probes, nil
}
