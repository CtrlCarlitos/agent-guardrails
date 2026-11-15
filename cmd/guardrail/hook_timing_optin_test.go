package main

import (
	"bytes"
	"encoding/json"
	"github.com/CtrlCarlitos/agent-guardrails/internal/adapter"
	"github.com/CtrlCarlitos/agent-guardrails/internal/daemon"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestHookTimingOptInCorrelatesAudit(t *testing.T) {
	for _, opt := range []string{"", "true", "1"} {
		t.Run("opt="+opt, func(t *testing.T) {
			testenv.SetState(t, t.TempDir())
			testenv.SetConfig(t, t.TempDir())
			t.Setenv("GUARDRAIL_CONFIG", "")
			t.Setenv("GUARDRAIL_TIMING", opt)
			old := engineDaemonEndpoint
			engineDaemonEndpoint = filepath.Join(t.TempDir(), "absent.sock")
			t.Cleanup(func() { engineDaemonEndpoint = old })
			repo := hostTestRepo(t)
			payload := mustJSON(t, map[string]any{"session_id": "timing-530", "call_id": "call-530", "event": "pre", "cwd": repo, "tool": "read", "paths": []string{filepath.Join(repo, "README.md")}})
			var out, stderr bytes.Buffer
			if code := run([]string{"hook", "opencode"}, bytes.NewReader(payload), &out, &stderr); code != 0 {
				t.Fatalf("exit=%d: %s", code, &stderr)
			}
			path := filepath.Join(filepath.Dir(audit.DefaultPath("")), "hook-timing.jsonl")
			raw, err := os.ReadFile(path)
			if opt != "1" {
				for _, rec := range auditRecords(t) {
					if rec.HookMS != 0 || rec.StartupMS != 0 {
						t.Errorf("default audit emitted timing: %+v", rec)
					}
				}
				if !os.IsNotExist(err) {
					t.Fatalf("default emitted timing: %s, %v", raw, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var sample struct {
				Host, Version, Transport string
				CallID                   string `json:"call_id"`
				Phases                   map[string]*float64
			}
			if err := json.Unmarshal(bytes.TrimSpace(raw), &sample); err != nil {
				t.Fatal(err)
			}
			if sample.Host != "opencode" || sample.Version != version || sample.Transport != "spawn" || sample.CallID != "call-530" {
				t.Fatalf("identity: %s", raw)
			}
			for _, key := range []string{"hook_total_ms", "daemon_dial_ms", "engine_handling_ms", "response_write_ms", "adapter_parse_ms", "policy_setup_ms", "audit_write_ms", "response_encode_write_ms"} {
				if sample.Phases[key] == nil {
					t.Errorf("missing measured %s: %s", key, raw)
				}
			}
			for _, key := range []string{"host_dispatch_ms", "wrapper_dispatch_ms"} {
				v, ok := sample.Phases[key]
				if !ok || v != nil {
					t.Errorf("%s must be explicitly unmeasured: %s", key, raw)
				}
			}
			recs := auditRecords(t)
			data, _ := json.Marshal(recs[len(recs)-1])
			if !strings.Contains(string(data), `"call_id":"call-530"`) || !strings.Contains(string(data), `"guardrail_version":`) {
				t.Errorf("audit correlation missing: %s", data)
			}
		})
	}
}

func TestHookTimingDaemonPhases(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	t.Setenv("GUARDRAIL_TIMING", "1")
	useEngineDaemon(t)
	repo := hostTestRepo(t)
	payload := mustJSON(t, map[string]any{"session_id": "daemon-timing", "call_id": "daemon-call", "event": "pre", "cwd": repo, "tool": "read", "paths": []string{filepath.Join(repo, "README.md")}})
	tc, err := adapter.ParseOpencode(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	client, err := daemon.Dial(engineDaemonEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// A direct client avoids competing native-hook samples: sampling deliberately
	// drops on lock contention. The response observer runs after the client has
	// received the response, so wait for its log write rather than racing it.
	v, err := client.Evaluate(tc)
	if err != nil || string(v.Decision) != "allow" {
		t.Fatalf("evaluate: %+v %v", v, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var raw []byte
	var engineSeen, responseSeen bool
	for time.Now().Before(deadline) {
		raw, _ = os.ReadFile(audit.TimingPath())
		engineSeen, responseSeen = false, false
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var sample audit.TimingSample
			if json.Unmarshal(line, &sample) != nil {
				continue
			}
			if sample.Transport != "daemon" || sample.CallID != "daemon-call" {
				continue
			}
			if sample.Kind == "daemon-engine" && sample.Phases["engine_handling_ms"] != nil {
				engineSeen = true
			}
			if sample.Kind == "daemon-response" && sample.Phases["response_write_ms"] != nil {
				responseSeen = true
			}
		}
		if engineSeen && responseSeen {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing daemon engine=%v response=%v:\n%s", engineSeen, responseSeen, raw)
}

func TestTimingDoctorSeparatesVersionsAndUnmeasuredPhases(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	t.Setenv("GUARDRAIL_TIMING", "1")
	ms := float64(2)
	for _, v := range []string{"v-old", "v-new"} {
		sample := audit.TimingSample{Kind: "hook", Host: "opencode", Version: v, Transport: "spawn", SessionID: "s-" + v, CallID: "same-call", Phases: map[string]*float64{"engine_handling_ms": &ms, "host_dispatch_ms": nil}}
		if err := audit.WriteTiming(sample); err != nil {
			t.Fatal(err)
		}
	}
	plugin := `{"kind":"plugin","host":"opencode","session_id":"s-v-new","call_id":"same-call","transport":"spawn","runtime":"node fixture","phases":{"wrapper_dispatch_ms":1,"host_dispatch_ms":null}}` + "\n"
	if err := os.WriteFile(filepath.Join(filepath.Dir(audit.TimingPath()), "plugin-timing.jsonl"), []byte(plugin), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printOptInTiming(&out)
	for _, want := range []string{"version=v-old", "version=v-new", "kind=plugin", "host_dispatch_ms=unmeasured", "host_version=unmeasured"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q:\n%s", want, &out)
		}
	}
	if strings.Contains(out.String(), " version=unmeasured ") {
		t.Errorf("plugin did not correlate exact session/call:\n%s", &out)
	}
	t.Setenv("GUARDRAIL_TIMING", "")
	out.Reset()
	printOptInTiming(&out)
	if out.Len() != 0 {
		t.Fatalf("default doctor emitted timing: %s", &out)
	}
}

func TestTimingWriteFailureDoesNotChangeVerdict(t *testing.T) {
	testenv.SetState(t, t.TempDir())
	testenv.SetConfig(t, t.TempDir())
	t.Setenv("GUARDRAIL_CONFIG", "")
	old := engineDaemonEndpoint
	engineDaemonEndpoint = filepath.Join(t.TempDir(), "absent.sock")
	t.Cleanup(func() { engineDaemonEndpoint = old })
	repo := hostTestRepo(t)
	if err := os.MkdirAll(audit.TimingPath(), 0700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"git status", "git push --force origin main"} {
		payload := mustJSON(t, map[string]any{"session_id": "timing-failure", "call_id": "call-failure", "event": "pre", "cwd": repo, "tool": "bash", "command": command, "arguments": map[string]any{"command": command}})
		var beforeOut, beforeErr, afterOut, afterErr bytes.Buffer
		t.Setenv("GUARDRAIL_TIMING", "")
		before := run([]string{"hook", "opencode"}, bytes.NewReader(payload), &beforeOut, &beforeErr)
		t.Setenv("GUARDRAIL_TIMING", "1")
		after := run([]string{"hook", "opencode"}, bytes.NewReader(payload), &afterOut, &afterErr)
		if before != after || beforeOut.String() != afterOut.String() || beforeErr.String() != afterErr.String() {
			t.Fatalf("timing changed %q: before=%d/%s/%s after=%d/%s/%s", command, before, &beforeOut, &beforeErr, after, &afterOut, &afterErr)
		}
		if strings.Contains(command, "--force") && after != 2 {
			t.Fatalf("force push lost denial: %d %s", after, &afterOut)
		}
	}
}
