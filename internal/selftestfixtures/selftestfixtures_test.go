package selftestfixtures

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadServesEveryPlaneAndPlatformVariants(t *testing.T) {
	t.Run("posix", func(t *testing.T) {
		for _, goos := range []string{"linux", "darwin"} {
			probes, err := Load(goos)
			if err != nil {
				t.Fatalf("Load(%q): %v", goos, err)
			}
			if len(probes) < 19 {
				t.Fatalf("Load(%q) = %d probes, want at least 19", goos, len(probes))
			}
			byPlane := map[string]int{}
			byKey := map[string]Probe{}
			for _, p := range probes {
				byPlane[p.Plane]++
				byKey[p.Plane+"/"+p.File] = p
			}
			for _, plane := range []string{"claude", "opencode", "antigravity", "codex"} {
				if byPlane[plane] == 0 {
					t.Errorf("Load(%q): plane %q has 0 probes", goos, plane)
				}
			}
			// Spot-check canonical probes across planes and hook args derivation.
			if p, ok := byKey["claude/serena-secret-mutation-denies.json"]; !ok || p.WantDecision != "deny" || p.WantRuleID != "P4.secret-path" || !slices.Equal(p.Args, []string{"claude"}) {
				t.Errorf("Load(%q): unexpected claude serena probe: %+v", goos, p)
			}
			if p, ok := byKey["antigravity/destructive-run-command-denies.json"]; !ok || p.WantDecision != "deny" || !slices.Equal(p.Args, []string{"antigravity", "pre"}) {
				t.Errorf("Load(%q): unexpected antigravity destructive probe: %+v", goos, p)
			}
			if p, ok := byKey["codex/destructive-denies.json"]; !ok || p.WantDecision != "deny" || p.WantRuleID != "P1.rm-rf" || !strings.Contains(p.Payload, `"rm -rf /"`) {
				t.Errorf("Load(%q): unexpected codex destructive probe: %+v", goos, p)
			}
			// TempDir placeholder must be resolved to os.TempDir().
			var codexPayload struct {
				CWD string `json:"cwd"`
			}
			if err := json.Unmarshal([]byte(byKey["codex/benign-command-allows.json"].Payload), &codexPayload); err != nil {
				t.Fatalf("codex payload invalid JSON: %v", err)
			}
			if codexPayload.CWD != os.TempDir() {
				t.Errorf("Load(%q): codex cwd = %q, want %q", goos, codexPayload.CWD, os.TempDir())
			}
		}
	})

	t.Run("windows_overrides_and_additions", func(t *testing.T) {
		linuxProbes, err := Load("linux")
		if err != nil {
			t.Fatalf("Load(linux): %v", err)
		}
		winProbes, err := Load("windows")
		if err != nil {
			t.Fatalf("Load(windows): %v", err)
		}
		if len(winProbes) != len(linuxProbes)+4 {
			t.Fatalf("Load(windows) = %d probes, want %d (linux %d + 4 windows claude probes)", len(winProbes), len(linuxProbes)+4, len(linuxProbes))
		}
		byKey := map[string]Probe{}
		for _, p := range winProbes {
			byKey[p.Plane+"/"+p.File] = p
		}
		// Codex windows overrides replace POSIX entries in place.
		if p, ok := byKey["codex/benign-command-allows.json"]; !ok || p.WantDecision != "exit-2" {
			t.Errorf("Load(windows): codex benign override = %+v, want exit-2", p)
		}
		if p, ok := byKey["codex/destructive-denies.json"]; !ok || !strings.Contains(p.Payload, `rm -rf C:\\`) {
			t.Errorf("Load(windows): codex destructive override = %+v, want rm -rf C:\\\\", p)
		}
		// Claude windows additions load via LoadPlatformVariants too.
		variants, err := LoadPlatformVariants("windows")
		if err != nil {
			t.Fatalf("LoadPlatformVariants(windows): %v", err)
		}
		if len(variants) < 6 {
			t.Fatalf("LoadPlatformVariants(windows) = %d, want at least 6 (4 claude + 2 codex)", len(variants))
		}
	})
}

func TestLoadFromFSErrorsLoudlyOnMismatches(t *testing.T) {
	t.Run("missing_payload", func(t *testing.T) {
		fsys := fstest.MapFS{
			"fixtures/claude/expected.json": &fstest.MapFile{
				Data: []byte(`{"missing.json":{"decision":"deny"}}`),
			},
		}
		_, err := LoadFromFS(fsys, "linux")
		if err == nil || !strings.Contains(err.Error(), "missing.json") {
			t.Fatalf("expected error naming missing.json, got: %v", err)
		}
	})

	t.Run("orphan_payload", func(t *testing.T) {
		fsys := fstest.MapFS{
			"fixtures/claude/expected.json": &fstest.MapFile{
				Data: []byte(`{"good.json":{"decision":"allow"}}`),
			},
			"fixtures/claude/good.json": &fstest.MapFile{
				Data: []byte(`{"ok":true}`),
			},
			"fixtures/claude/orphan.json": &fstest.MapFile{
				Data: []byte(`{"ok":true}`),
			},
		}
		_, err := LoadFromFS(fsys, "linux")
		if err == nil || !strings.Contains(err.Error(), "orphan.json") {
			t.Fatalf("expected error naming orphan.json, got: %v", err)
		}
	})

	t.Run("empty_plane_dir", func(t *testing.T) {
		fsys := fstest.MapFS{
			"fixtures/claude/expected.json": &fstest.MapFile{
				Data: []byte(`{}`),
			},
		}
		_, err := LoadFromFS(fsys, "linux")
		if err == nil || !strings.Contains(err.Error(), "zero expectations") {
			t.Fatalf("expected error for empty plane expectations, got: %v", err)
		}
	})

	t.Run("empty_decision", func(t *testing.T) {
		fsys := fstest.MapFS{
			"fixtures/claude/expected.json": &fstest.MapFile{
				Data: []byte(`{"bad.json":{"name":"bad","decision":""}}`),
			},
			"fixtures/claude/bad.json": &fstest.MapFile{
				Data: []byte(`{"ok":true}`),
			},
		}
		_, err := LoadFromFS(fsys, "linux")
		if err == nil || !strings.Contains(err.Error(), "empty decision") {
			t.Fatalf("expected error for empty decision, got: %v", err)
		}
	})

	t.Run("invalid_payload_json", func(t *testing.T) {
		fsys := fstest.MapFS{
			"fixtures/claude/expected.json": &fstest.MapFile{
				Data: []byte(`{"broken.json":{"decision":"deny"}}`),
			},
			"fixtures/claude/broken.json": &fstest.MapFile{
				Data: []byte(`{not-json`),
			},
		}
		_, err := LoadFromFS(fsys, "linux")
		if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
			t.Fatalf("expected invalid JSON error, got: %v", err)
		}
	})
}
