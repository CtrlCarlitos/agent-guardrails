package test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/selftestfixtures"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// TestWindowsAndPOSIXSelftestFixturesContract verifies the shared embedded
// selftest fixture tree (#107) on both POSIX and Windows:
//   - Every OS matrix (linux, darwin, windows) loads cleanly, carries valid
//     JSON payloads, pins a decision, and includes the "selftest" marking
//     literal (#600).
//   - Every fixture for the current host executes through the built binary's
//     real `guardrail hook <plane>` path and matches its expected verdict and
//     rule ID.
func TestWindowsAndPOSIXSelftestFixturesContract(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		probes, err := selftestfixtures.Load(goos)
		if err != nil {
			t.Fatalf("Load(%q): %v", goos, err)
		}
		if len(probes) < 19 {
			t.Fatalf("Load(%q): got %d probes, want at least 19", goos, len(probes))
		}
		planes := map[string]int{}
		for _, p := range probes {
			planes[p.Plane]++
			if len(p.Args) == 0 {
				t.Errorf("%s/%s/%s: empty hook args", goos, p.Plane, p.File)
			}
			if !json.Valid([]byte(p.Payload)) {
				t.Errorf("%s/%s/%s: invalid JSON payload", goos, p.Plane, p.File)
			}
			if !strings.Contains(p.Payload, "selftest") {
				t.Errorf("%s/%s/%s: payload lacks \"selftest\" marking literal", goos, p.Plane, p.File)
			}
			switch p.WantDecision {
			case "allow", "ask", "deny", "exit-2":
			default:
				t.Errorf("%s/%s/%s: unexpected decision %q", goos, p.Plane, p.File, p.WantDecision)
			}
		}
		for _, plane := range []string{"claude", "opencode", "antigravity", "codex"} {
			if planes[plane] == 0 {
				t.Errorf("Load(%q): plane %q has 0 probes", goos, plane)
			}
		}
		if goos == "windows" && planes["claude"] < 11 {
			t.Errorf("Load(windows): claude has %d probes, want at least 11 (base + windows variants)", planes["claude"])
		}
	}

	bin := buildBinary(t)
	hostProbes, err := selftestfixtures.Load(runtime.GOOS)
	if err != nil {
		t.Fatalf("Load(%q): %v", runtime.GOOS, err)
	}
	for _, probe := range hostProbes {
		probe := probe
		t.Run(probe.Plane+"/"+probe.File, func(t *testing.T) {
			roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
			suffix := "selftest-contract-" + probe.Plane
			payload := strings.ReplaceAll(probe.Payload, "selftest", suffix)
			args := append([]string{"hook"}, probe.Args...)
			cmd := exec.Command(bin, args...)
			cmd.Stdin = bytes.NewReader([]byte(payload))
			cmd.Env = testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			_ = cmd.Run()
			code := cmd.ProcessState.ExitCode()

			decision, ruleID := parseContractSelftestVerdict(code, stdout.String(), stderr.String())
			if ruleID == "" && probe.WantRuleID != "" {
				auditPath := filepath.Join(roots.State, "guardrail", "audit.jsonl")
				if raw, err := os.ReadFile(auditPath); err == nil {
					lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
					for i := len(lines) - 1; i >= 0; i-- {
						var rec struct {
							SessionID string `json:"session_id"`
							RuleID    string `json:"rule_id"`
						}
						if json.Unmarshal([]byte(lines[i]), &rec) == nil && rec.SessionID == suffix {
							ruleID = rec.RuleID
							break
						}
					}
				}
			}
			if decision != probe.WantDecision || (probe.WantRuleID != "" && ruleID != probe.WantRuleID) {
				t.Fatalf("%s (%s): got %s/%s (exit %d, stdout %q, stderr %q), want %s/%s",
					probe.File, probe.Name, decision, ruleID, code, stdout.String(), stderr.String(),
					probe.WantDecision, probe.WantRuleID)
			}
		})
	}
}

func parseContractSelftestVerdict(code int, stdout, stderr string) (decision, ruleID string) {
	var payload struct {
		Decision string `json:"decision"`
		RuleID   string `json:"rule_id"`
		Hook     *struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &payload); err == nil {
		if payload.Decision != "" {
			if payload.Decision == "force_ask" {
				payload.Decision = "ask"
			}
			return payload.Decision, payload.RuleID
		}
		if payload.Hook != nil && payload.Hook.PermissionDecision != "" {
			d := payload.Hook.PermissionDecision
			if d == "force_ask" {
				d = "ask"
			}
			return d, ""
		}
	}
	if strings.Contains(stderr, "Guardrail denied this action") {
		return "deny", ""
	}
	if strings.Contains(stderr, "Operator authorization required") {
		return "ask", ""
	}
	if code == 0 {
		return "allow", ""
	}
	return "exit-" + itoa(code), ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		digits[i] = '-'
	}
	return string(digits[i:])
}
