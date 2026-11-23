package adapter

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsCodexCouncilCompatibility(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	const bash = `& 'C:\Program Files\Git\bin\bash.exe' -c '`
	for _, resumed := range []bool{false, true} {
		name := "fresh"
		if resumed {
			name = "resumed"
		}
		t.Run(name, func(t *testing.T) {
			repo := t.TempDir()
			var envelope map[string]any
			if err := json.Unmarshal(codexPayload(t, repo, "pwsh", false), &envelope); err != nil {
				t.Fatal(err)
			}
			if resumed {
				path := envelope["transcript_path"].(string)
				session := envelope["session_id"].(string)
				head, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				_, body, _ := strings.Cut(string(head), "\n")
				meta := `{"type":"session_meta","payload":{"id":"` + session + `"}}` + "\n"
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "rollout-resumed-"+session+".jsonl"), []byte(meta+body), 0600); err != nil {
					t.Fatal(err)
				}
				delete(envelope, "transcript_path")
			}
			for _, probe := range []struct {
				step, command, rule string
			}{
				{"discovery", `$PSVersionTable.PSVersion; $PSVersionTable.PSEdition; (Get-Command git).Source`, ""},
				{"Git Bash", bash + `echo $BASH_VERSION; uname -s'`, ""},
				{"before state", bash + `git rev-parse HEAD'`, ""},
				{"unresolved ref", bash + `git rev-parse $ref'`, "P3.unresolved"},
				{"unresolved redirect", bash + `git rev-parse HEAD > $path'`, "P3.unresolved"},
				{"worktree create", bash + `git worktree add --detach .worktrees/council/example/member HEAD'`, "P3.unresolved"},
			} {
				t.Run(probe.step, func(t *testing.T) {
					envelope["tool_input"] = map[string]string{"command": probe.command}
					raw, err := json.Marshal(envelope)
					if err != nil {
						t.Fatal(err)
					}
					call, err := ParseCodex(bytes.NewReader(raw))
					if err != nil || call.Shell != engine.ShellPowerShell {
						t.Fatalf("PowerShell proof: shell=%q diagnostic=%q error=%v", call.Shell, call.ShellDiagnostic, err)
					}
					v := engine.Evaluate(call, pol)
					var out, stderr bytes.Buffer
					code := EmitCodex(v, "pre", call, &out, &stderr)
					if probe.rule != "" {
						if v.Decision != policy.Ask || v.RuleID != probe.rule || !strings.Contains(stderr.String(), probe.rule) || out.Len() != 0 {
							t.Fatalf("Guardrail verdict=%+v, stdout=%q, stderr=%q", v, out.String(), stderr.String())
						}
						return
					}
					if v.Decision != policy.Allow || code != 0 {
						t.Fatalf("Guardrail verdict=%+v, exit=%d, stderr=%q", v, code, stderr.String())
					}
					if command := updatedCommand(t, out.String()); !strings.Contains(command, "(Get-Location).ProviderPath") ||
						!strings.HasSuffix(command, "\n"+probe.command) {
						t.Fatalf("working-directory precondition or original command missing: %q", command)
					}
				})
			}
		})
	}
}
