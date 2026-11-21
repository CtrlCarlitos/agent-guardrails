package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// TestWindowsAndPOSIXStabilityPolicyMatchesCode mechanically verifies that
// docs/stability-policy.md stays in step with the shipped Operator config
// schema, Overlay schema, additive stable CLI commands, ADR-0035 posture
// rules, and the compiled binary's exit-code contract (#103).
func TestWindowsAndPOSIXStabilityPolicyMatchesCode(t *testing.T) {
	root := docsRepoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "docs", "stability-policy.md"))
	if err != nil {
		t.Fatalf("read docs/stability-policy.md: %v", err)
	}
	doc := string(raw)

	t.Run("operator_config_schema", func(t *testing.T) {
		// Every TOML key on policy.RepoGrant must be named in the Operator config section.
		grantType := reflect.TypeOf(policy.RepoGrant{})
		for i := 0; i < grantType.NumField(); i++ {
			tag := grantType.Field(i).Tag.Get("toml")
			key := strings.Split(tag, ",")[0]
			if key == "" || key == "-" {
				continue
			}
			if !strings.Contains(doc, key) {
				t.Errorf("docs/stability-policy.md does not document RepoGrant key %q", key)
			}
		}
		for _, topKey := range []string{"approval", "web_hosts", "web_research"} {
			if !strings.Contains(doc, topKey) {
				t.Errorf("docs/stability-policy.md does not document top-level Operator config key %q", topKey)
			}
		}
	})

	t.Run("overlay_schema", func(t *testing.T) {
		overlayKeys := []string{
			"engine_min_version",
			"audit_log",
			"unknown_tool_posture",
			"waive",
			"safe_roots",
			"secret_dirs",
			"secret_globs",
			"secret_ask_globs",
			"secret_allow",
			"egress_allowlist",
			"web_hosts",
			"recipes.odoo",
			"`id`",
			"`tool`",
			"`pattern`",
			"`decision`",
			"`reason`",
		}
		for _, key := range overlayKeys {
			if !strings.Contains(doc, key) {
				t.Errorf("docs/stability-policy.md does not document Overlay key %q", key)
			}
		}
	})

	t.Run("stable_cli_and_exit_code_clauses", func(t *testing.T) {
		requiredClauses := []string{
			"guardrail status",
			"guardrail tail",
			"audit --follow",
			"guardrail report",
			"guardrail delivery",
			"operator trust",
			"night on",
			"--scope",
			"--major",
			"ADR-0035",
			"proof.json",
			"explain",
			"2026-11-21",
		}
		for _, want := range requiredClauses {
			if !strings.Contains(doc, want) {
				t.Errorf("docs/stability-policy.md missing %q", want)
			}
		}

		// Pin the exit-code table specifically so new exit-1 / exit-3 callers stay documented.
		exitSectionStart := strings.Index(doc, "**Exit-code contract.**")
		exitSectionEnd := strings.Index(doc, "### Overlay format")
		if exitSectionStart < 0 || exitSectionEnd <= exitSectionStart {
			t.Fatal("could not locate Exit-code contract section in docs/stability-policy.md")
		}
		exitSection := doc[exitSectionStart:exitSectionEnd]
		for _, want := range []string{
			"`selftest`",
			"`delivery enable`",
			"`approvals grant`",
			"`operator trust|untrust`",
		} {
			if !strings.Contains(exitSection, want) {
				t.Errorf("docs/stability-policy.md exit-code table missing %s", want)
			}
		}
	})

	t.Run("compiled_binary_exit_code_contract", func(t *testing.T) {
		bin := buildBinary(t)
		roots := testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}
		env := testenv.ChildProcessEnv(roots, "GUARDRAIL_CONFIG=")

		cases := []struct {
			name     string
			args     []string
			wantCode int
		}{
			{"version_exit_0", []string{"version"}, 0},
			{"help_exit_0", []string{"help"}, 0},
			{"night_status_inactive_exit_1", []string{"night", "status"}, 1},
			{"explain_empty_exit_1", []string{"explain"}, 1},
			{"report_empty_exit_1", []string{"report"}, 1},
			{"unknown_subcommand_exit_2", []string{"nonexistent-subcommand"}, 2},
			{"no_args_exit_2", nil, 2},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				cmd := exec.Command(bin, tc.args...)
				cmd.Env = env
				cmd.Dir = roots.Home
				out, _ := cmd.CombinedOutput()
				if got := cmd.ProcessState.ExitCode(); got != tc.wantCode {
					t.Fatalf("guardrail %v exited %d, want %d\noutput:\n%s", tc.args, got, tc.wantCode, string(out))
				}
			})
		}
	})
}
