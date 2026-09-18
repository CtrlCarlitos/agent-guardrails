package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorCodexCoverage(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
		exit         int
		want         string
	}{
		{"known", `[{"type":"function","name":"exec_command","parameters":{}}]`, 0, "Bash\tcommand\tcontracted"},
		{"unknown", `[{"type":"function","name":"brand_new","parameters":{}}]`, 1, "brand_new\tbrand_new\tunknown\tuncontracted"},
		{"hosted", `[{"type":"web_search"}]`, 1, "hosted-no-local-hook"},
		{"code mode", `[{"type":"function","name":"exec","parameters":{}}]`, 0, "deny\tcontracted"},
		{"malformed", `{}`, 2, "incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tools.json")
			if err := os.WriteFile(path, []byte(tc.schema), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			code := run([]string{"doctor", "--coverage", "codex", "--schema", path}, strings.NewReader(""), &out, &errb)
			if code != tc.exit || !strings.Contains(out.String()+errb.String(), tc.want) {
				t.Fatalf("exit %d; stdout %s; stderr %s", code, &out, &errb)
			}
			if code != 2 && (!strings.Contains(out.String(), "not a complete runtime inventory") || !strings.Contains(out.String(), "not proven retired")) {
				t.Fatalf("missing scope: %s", &out)
			}
		})
	}
}

func TestDoctorCodexCoverageArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--coverage"}, {"--coverage", "codex"}, {"--schema", "x"},
		{"--coverage", "other", "--schema", "x"},
		{"--coverage", "codex", "--coverage", "codex", "--schema", "x"},
		{"--coverage", "codex", "--schema", "x", "--schema", "y"},
	} {
		var out, errb bytes.Buffer
		if code := cmdDoctor(args, &out, &errb); code != 2 {
			t.Errorf("args %v: exit %d", args, code)
		}
	}
}

func TestDoctorCoveragePlaneSpecificFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"codex", []string{"--coverage", "codex", "--schema", "tools.json"}, true},
		{"codex reversed", []string{"--schema", "tools.json", "--coverage", "codex"}, true},
		{"claude", []string{"--coverage", "claude", "--bundle", "cli.js"}, true},
		{"antigravity", []string{"--coverage", "antigravity", "--config", "mcp.json", "--schemas", "schemas"}, true},
		{"schema without plane", []string{"--schema", "tools.json"}, false},
		{"schema without value", []string{"--coverage", "codex", "--schema"}, false},
		{"claude schema", []string{"--coverage", "claude", "--schema", "tools.json"}, false},
		{"antigravity schema", []string{"--coverage", "antigravity", "--schema", "tools.json"}, false},
		{"codex config", []string{"--coverage", "codex", "--schema", "tools.json", "--config", "mcp.json"}, false},
		{"codex schemas", []string{"--coverage", "codex", "--schema", "tools.json", "--schemas", "schemas"}, false},
		{"codex bundle", []string{"--coverage", "codex", "--schema", "tools.json", "--bundle", "cli.js"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errb bytes.Buffer
			opts, ok := parseDoctorArgs(tc.args, &errb)
			if ok != tc.want {
				t.Fatalf("accepted = %v, want %v: %s", ok, tc.want, &errb)
			}
			if ok && opts.coverage == "codex" && opts.schema != "tools.json" {
				t.Fatalf("schema = %q", opts.schema)
			}
		})
	}
}
