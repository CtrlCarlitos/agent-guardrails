package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

func TestCodexFloorDriftRepair(t *testing.T) {
	for _, damage := range []string{"missing file", "missing rule", "weakened rule", "unreadable file"} {
		t.Run(damage, func(t *testing.T) {
			driftSandbox(t)
			t.Setenv("CODEX_HOME", filepath.Join(t.TempDir(), "custom-codex"))
			enableForDrift(t, "codex")
			hooks, err := planeConfigPath("codex")
			if err != nil {
				t.Fatal(err)
			}
			rules := filepath.Join(filepath.Dir(hooks), "rules", "guardrail.rules")
			if n := planeFloorDrift("codex"); n != 0 {
				t.Fatalf("fresh floor drift = %d", n)
			}
			raw := genconfig.CodexRules()
			wantMissing := 1
			switch damage {
			case "missing file":
				if err := os.Remove(rules); err != nil {
					t.Fatal(err)
				}
			case "missing rule":
				lines := strings.Split(string(raw), "\n")
				raw = []byte(strings.Join(append(lines[:1], lines[2:]...), "\n"))
				if err := os.WriteFile(rules, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "weakened rule":
				raw = bytes.Replace(raw, []byte(`decision = "forbidden"`), []byte(`decision = "allow"`), 1)
				if err := os.WriteFile(rules, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "unreadable file":
				if err := os.Remove(rules); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(rules, 0700); err != nil {
					t.Fatal(err)
				}
			}
			doc, err := genconfig.ReadJSONObject(hooks)
			if err != nil || !genconfig.CodexHooksRegistered(doc) {
				t.Fatal("fixture lost hook registration")
			}
			if n := planeFloorDrift("codex"); n != wantMissing {
				t.Errorf("floor drift = %d, want %d", n, wantMissing)
			}
			reason, err := setupEnableReason("codex")
			if err != nil || !strings.Contains(reason, "floor drifted") {
				t.Errorf("setup reason = %q, %v", reason, err)
			}
			var out, stderr bytes.Buffer
			_, problems := printDoctor(&out, &stderr)
			if problems == 0 || !strings.Contains(out.String(), "codex native floor: WARNING") {
				t.Errorf("doctor missed floor drift:\n%s\n%s", &out, &stderr)
			}
			if damage == "unreadable file" {
				if err := enablePlaneIntegrationMode("codex", true, false); err == nil {
					t.Fatal("repair must report an unreadable owned path")
				}
				if err := os.Remove(rules); err != nil {
					t.Fatal(err)
				}
			}
			if err := enablePlaneIntegrationMode("codex", true, false); err != nil {
				t.Fatal(err)
			}
			if n := planeFloorDrift("codex"); n != 0 {
				t.Errorf("repaired floor drift = %d", n)
			}
			if reason, err := setupEnableReason("codex"); err != nil || reason != "" {
				t.Errorf("after repair: %q, %v", reason, err)
			}
			out.Reset()
			stderr.Reset()
			printDoctor(&out, &stderr)
			if !strings.Contains(out.String(), "codex native floor: matches generated rules") {
				t.Errorf("doctor missed healthy floor:\n%s", &out)
			}
		})
	}
}
