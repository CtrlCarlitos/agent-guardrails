package coverage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsCodexRuntimeSchemasMatchNativeRegistry(t *testing.T) {
	fixtures, err := filepath.Glob("testdata/codex-*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) == 0 {
		t.Fatal("no captured Codex runtime schemas")
	}

	// Codex CLI 0.154.0 exposed these model tools but did not produce matching
	// hook-visible identities for them. Keep the historical capture without
	// pretending it established enforcement coverage.
	exceptions := map[string]bool{
		"codex-direct.json:multi_agent_v1.close_agent":  false,
		"codex-direct.json:multi_agent_v1.resume_agent": false,
		"codex-direct.json:multi_agent_v1.send_input":   false,
		"codex-direct.json:multi_agent_v1.wait_agent":   false,
	}

	for _, path := range fixtures {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			inv, err := ScanCodexSchema(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range inv.Tools {
				if row.Status != "uncontracted" && row.Status != "unsupported-schema" {
					continue
				}
				key := filepath.Base(path) + ":" + row.Name
				if _, ok := exceptions[key]; ok && row.Status == "uncontracted" {
					exceptions[key] = true
					continue
				}
				t.Errorf("captured tool %q projects to hook identity %q with status %q; classify it in the native registry or document a runtime-evidenced exception", row.Name, row.Hook, row.Status)
			}
		})
	}
	for key, observed := range exceptions {
		if !observed {
			t.Errorf("stale Codex schema exception %s; remove it or restore the evidenced row", key)
		}
	}
}
