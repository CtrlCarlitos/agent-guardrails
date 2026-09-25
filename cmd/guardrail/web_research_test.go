package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/approval"
	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func webResearchTestState(t *testing.T, config string) string {
	t.Helper()
	testenv.SetHome(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	t.Setenv("GUARDRAIL_CODEX_STRUCTURED_WINDOWS", "")
	if config != "" {
		path := policy.OperatorConfigPath()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return t.TempDir()
}

func TestWindowsWebResearchFreshDefaultAndUpgradeSafety(t *testing.T) {
	for _, existing := range []string{"fresh", "config-dir", "state-dir", "legacy-hooks", "damaged-host-config", "explicit-on", "malformed"} {
		t.Run(existing, func(t *testing.T) {
			webResearchTestState(t, "")
			dir, _ := policy.OperatorConfigDir()
			switch existing {
			case "config-dir":
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			case "state-dir":
				path, err := genconfig.ManifestDir()
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
			case "legacy-hooks":
				path, err := planeConfigPath("codex")
				if err != nil {
					t.Fatal(err)
				}
				writePlaneSettings(t, path, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"guardrail hook codex"}]}]}}`)
			case "damaged-host-config":
				path, err := planeConfigPath("codex")
				if err != nil {
					t.Fatal(err)
				}
				writePlaneSettings(t, path, `{"hooks":`)
			case "explicit-on", "malformed":
				body := "[web_research]\nenforcement = \"on\"\n"
				if existing == "malformed" {
					body = "bad = ["
				}
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(policy.OperatorConfigPath(), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			if err := initializeWebResearchDefault(&out); err != nil {
				t.Fatal(err)
			}
			op, err := policy.LoadOperatorConfig()
			if existing != "malformed" && err != nil {
				t.Fatal(err)
			}
			if (op.WebResearchEnforcement == "off") != (existing == "fresh") {
				t.Fatalf("existing=%s mode=%s", existing, op.WebResearchEnforcement)
			}
			if err := initializeWebResearchDefault(&out); err != nil {
				t.Fatal(err)
			}
			if strings.Count(out.String(), "fresh installation default") > 1 {
				t.Fatal("bootstrap repeated")
			}
		})
	}
}

func TestWindowsWebResearchDefaultAuditFailureKeepsStrict(t *testing.T) {
	webResearchTestState(t, "")
	old := writeWebResearchDefaultAudit
	t.Cleanup(func() { writeWebResearchDefaultAudit = old })
	writeWebResearchDefaultAudit = func(audit.Record, string) error { return os.ErrPermission }
	var out bytes.Buffer
	if err := initializeWebResearchDefault(&out); err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil || op.WebResearchEnforcement == "off" || !strings.Contains(out.String(), "keeping strict") {
		t.Fatalf("op=%+v err=%v out=%s", op, err, out.String())
	}
}

func TestWindowsWebResearchDefaultDoesNotOverwriteConcurrentOperatorChoice(t *testing.T) {
	webResearchTestState(t, "")
	old := writeWebResearchDefaultAudit
	t.Cleanup(func() { writeWebResearchDefaultAudit = old })
	writeWebResearchDefaultAudit = func(r audit.Record, _ string) error {
		if r.Decision == "requested" {
			return setWebResearchEnforcement("on")
		}
		return nil
	}
	var out bytes.Buffer
	if err := initializeWebResearchDefault(&out); err != nil {
		t.Fatal(err)
	}
	op, err := policy.LoadOperatorConfig()
	if err != nil || op.WebResearchEnforcement != "on" || strings.Contains(out.String(), "enforcement: off") {
		t.Fatalf("overwrote concurrent choice: %+v %v out=%s", op, err, out.String())
	}
}

func TestWindowsWebResearchApprovalFailureDoesNotChangePolicy(t *testing.T) {
	for _, outcome := range []string{"not-enrolled", "submit-failed", "denied", "expired", "daemon-failed", "false-completion"} {
		t.Run(outcome, func(t *testing.T) {
			webResearchTestState(t, "[web_research]\nenforcement = \"on\"\n")
			stubOperatorEnrolled(t, outcome != "not-enrolled")
			oldSubmit, oldQuery := submitWebResearchRequest, queryWebResearchStatus
			t.Cleanup(func() { submitWebResearchRequest, queryWebResearchStatus = oldSubmit, oldQuery })
			submitWebResearchRequest = func(r approval.Request) (approval.Request, error) {
				if outcome == "not-enrolled" {
					t.Fatal("submitted without enrollment")
				}
				if outcome == "submit-failed" {
					return r, errors.New("WebAuthn unavailable")
				}
				r.ID = "fixture"
				r.ExpiresAt = time.Now().Add(time.Minute)
				return r, nil
			}
			queryWebResearchStatus = func(_, _ string) (approval.Request, error) {
				if outcome == "daemon-failed" {
					return approval.Request{}, errors.New("offline")
				}
				status := outcome
				if outcome == "false-completion" {
					status = "completed"
				}
				return approval.Request{Status: status}, nil
			}
			var out, errb bytes.Buffer
			code := cmdWebResearch([]string{"off"}, true, &out, &errb)
			want := 1
			if outcome == "not-enrolled" {
				want = 3
			}
			if code != want {
				t.Fatalf("exit=%d want=%d stderr=%s", code, want, errb.String())
			}
			op, err := policy.LoadOperatorConfig()
			if err != nil || op.WebResearchEnforcement != "on" {
				t.Fatalf("policy changed: %+v %v", op, err)
			}
		})
	}
}

func TestWindowsWebResearchBrokerPersistsExactChoiceOnce(t *testing.T) {
	webResearchTestState(t, "")
	stubOperatorEnrolled(t, true)
	oldSubmit, oldQuery := submitWebResearchRequest, queryWebResearchStatus
	t.Cleanup(func() { submitWebResearchRequest, queryWebResearchStatus = oldSubmit, oldQuery })
	broker := approval.New()
	var id string
	submitWebResearchRequest = func(r approval.Request) (approval.Request, error) {
		created, err := broker.Create(r)
		if err != nil {
			return created, err
		}
		id = created.ID
		stored, err := broker.Request(id)
		if err != nil || stored.Parameters["enforcement"] != r.Parameters["enforcement"] || !strings.Contains(stored.Summary(), r.Parameters["enforcement"]) {
			t.Fatalf("request lost exact choice: %+v %v", stored, err)
		}
		// Exercises the broker/action seam, not a live WebAuthn ceremony.
		if err := broker.Approve(id, approval.GlobalScope); err != nil {
			t.Fatal(err)
		}
		return created, nil
	}
	queryWebResearchStatus = func(_, id string) (approval.Request, error) { return broker.Request(id) }
	for _, mode := range []string{"off", "on"} {
		var out, errb bytes.Buffer
		if code := cmdWebResearch([]string{mode}, true, &out, &errb); code != 0 {
			t.Fatalf("mode=%s exit=%d stderr=%s", mode, code, errb.String())
		}
		if err := broker.Approve(id, approval.GlobalScope); !errors.Is(err, approval.ErrConsumed) {
			t.Fatalf("retry=%v", err)
		}
		if !strings.Contains(out.String(), "web-research enforcement: "+mode) {
			t.Fatal(out.String())
		}
	}
}

func TestWindowsWebResearchSerializationPreservesOtherAuthorizations(t *testing.T) {
	root := webResearchTestState(t, "")
	op := &policy.OperatorConfig{GlobalWebHosts: []string{"example.com"}, Repos: map[string]policy.RepoGrant{root: {SecretAllow: true, Waive: []string{"test-rule"}}}}
	if err := writeOperatorConfig(op); err != nil {
		t.Fatal(err)
	}
	if err := setWebResearchEnforcement("off"); err != nil {
		t.Fatal(err)
	}
	if err := mutateCommandGrants(root, func(g []policy.CommandGrant) []policy.CommandGrant { return g }); err != nil {
		t.Fatal(err)
	}
	if err := applyGlobalWebHost("docs.example.com", true); err != nil {
		t.Fatal(err)
	}
	got, err := policy.LoadOperatorConfig()
	if err != nil || got.WebResearchEnforcement != "off" || !got.AllowsSecretAllow(root) || !got.AllowsGlobalWebHost("example.com") || !got.AllowsGlobalWebHost("docs.example.com") || !got.AllowsWaiver(root, "test-rule") {
		t.Fatalf("lost config: %+v %v", got, err)
	}
}

func TestWindowsWebResearchHooksStrictAndOff(t *testing.T) {
	for _, mode := range []string{"", "on", "off", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			config := ""
			if mode != "" {
				config = "[web_research]\nenforcement = \"" + mode + "\"\n"
			}
			cwd := webResearchTestState(t, config)
			for _, input := range []string{
				`{"search_query":[{"q":"public documentation"}]}`,
				`{"open":[{"ref_id":"https://example.com"},{"ref_id":"turn0search0"}]}`,
				`{"search_query":[{"q":"docs"}],"open":[{"ref_id":"turn0search0"}]}`,
				`{"click":[{"ref_id":"turn0search0","id":1}],"find":[{"ref_id":"turn0search0","pattern":"hook"}],"screenshot":[{"ref_id":"turn0search0","pageno":0}]}`,
			} {
				payload, _ := json.Marshal(map[string]any{"session_id": "web-research-fixture", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "web.run", "tool_input": json.RawMessage(input)})
				var out, errb bytes.Buffer
				code := cmdHook([]string{"codex"}, bytes.NewReader(payload), &out, &errb)
				want := 2
				if mode == "off" {
					want = 0
				}
				if code != want {
					t.Errorf("mode=%q input=%s exit=%d want=%d stderr=%s", mode, input, code, want, errb.String())
				}
			}
		})
	}
}

func TestWindowsWebResearchSwitchCannotBeChangedFromNonterminal(t *testing.T) {
	webResearchTestState(t, "")
	for _, mode := range []string{"on", "off"} {
		var out, errb bytes.Buffer
		if code := run([]string{"web-research", mode}, strings.NewReader("yes\n"), &out, &errb); code != 2 || !strings.Contains(errb.String(), "interactive local terminal") {
			t.Errorf("mode=%s exit=%d stderr=%s", mode, code, errb.String())
		}
		if _, err := os.Stat(policy.OperatorConfigPath()); !os.IsNotExist(err) {
			t.Fatalf("nonterminal changed config: %v", err)
		}
	}
}
