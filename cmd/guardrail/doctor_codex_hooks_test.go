package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
)

func TestDoctorCodexHooksReportsIndependentStagesAndDecodedCommand(t *testing.T) {
	dir := t.TempDir()
	hooksPath := filepath.Join(dir, "hooks.json")
	command := writeCodexDiagnosticConfig(t, hooksPath, `C:\Users\Agent User\.local\bin\guardrail.exe`)

	oldTrust, oldProbe, oldObservation := codexTrustInspector, codexHandlerProbe, codexRuntimeObserver
	t.Cleanup(func() {
		codexTrustInspector, codexHandlerProbe, codexRuntimeObserver = oldTrust, oldProbe, oldObservation
	})
	codexTrustInspector = func(context.Context, string) ([]codexTrustMetadata, error) {
		return []codexTrustMetadata{
			{EventName: "preToolUse", Command: command, CurrentHash: "sha256:pre", TrustStatus: "trusted", SourcePath: hooksPath},
			{EventName: "postToolUse", Command: command, CurrentHash: "sha256:post", TrustStatus: "trusted", SourcePath: hooksPath},
			{EventName: "sessionStart", Command: command, CurrentHash: "sha256:start", TrustStatus: "trusted", SourcePath: hooksPath},
		}, nil
	}
	codexHandlerProbe = func(context.Context, string, string) codexHandlerProbeResult {
		return codexHandlerProbeResult{Started: true, ExitCode: 2, Stderr: "guardrail: handler failure: malformed Codex hook payload; failing closed"}
	}
	codexRuntimeObserver = func() codexRuntimeObservation {
		return codexRuntimeObservation{DispatchObserved: true, Capabilities: []string{"command", "mutation"}}
	}

	var out, errb bytes.Buffer
	code := printCodexHookDiagnostics(hooksPath, dir, "windows", &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d; stdout=%s stderr=%s", code, &out, &errb)
	}
	got := out.String()
	for _, want := range []string{
		"registered: yes",
		"trusted: yes",
		"handler id: guardrail-codex-PreToolUse",
		"decoded effective command: $guardrailPath = 'C:\\Users\\Agent User\\.local\\bin\\guardrail.exe'",
		"handler failure: evaluator exited with code",
		"trust hash: sha256:pre",
		"direct exit code: 2",
		"direct stderr: guardrail: handler failure: malformed Codex hook payload; failing closed",
		"handler directly runnable: yes",
		"handler fail-closed: yes",
		"runtime dispatch observed: yes (heuristic)",
		"capabilities observed: command, mutation",
		"runtime coverage claim: none",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
}

func TestDoctorCodexHooksKeepsSilentAndFailOpenStatesRed(t *testing.T) {
	dir := t.TempDir()
	hooksPath := filepath.Join(dir, "hooks.json")
	command := writeCodexDiagnosticConfig(t, hooksPath, `C:\guardrail.exe`)

	oldTrust, oldProbe, oldObservation := codexTrustInspector, codexHandlerProbe, codexRuntimeObserver
	t.Cleanup(func() {
		codexTrustInspector, codexHandlerProbe, codexRuntimeObserver = oldTrust, oldProbe, oldObservation
	})
	codexTrustInspector = func(context.Context, string) ([]codexTrustMetadata, error) {
		return []codexTrustMetadata{{EventName: "preToolUse", Command: command, CurrentHash: "sha256:stale", TrustStatus: "modified", SourcePath: hooksPath}}, nil
	}
	codexHandlerProbe = func(context.Context, string, string) codexHandlerProbeResult {
		return codexHandlerProbeResult{Started: true, ExitCode: 0}
	}
	codexRuntimeObserver = func() codexRuntimeObservation { return codexRuntimeObservation{} }

	var out, errb bytes.Buffer
	code := printCodexHookDiagnostics(hooksPath, dir, "windows", &out, &errb)
	if code != 1 {
		t.Fatalf("exit %d; stdout=%s stderr=%s", code, &out, &errb)
	}
	got := out.String()
	for _, want := range []string{
		"trusted: no",
		"trust status: modified",
		"handler directly runnable: yes",
		"handler fail-closed: no",
		"runtime dispatch observed: no",
		"capabilities observed: none",
		"runtime coverage claim: none",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
}

func writeCodexDiagnosticConfig(t *testing.T, hooksPath, binary string) string {
	t.Helper()
	fragment := genconfig.CodexConfig(binary)
	raw, err := json.Marshal(fragment)
	if err != nil {
		t.Fatal(err)
	}
	writePlaneSettings(t, hooksPath, string(raw))
	hooks := fragment["hooks"].(map[string]any)
	group := hooks["PreToolUse"].([]any)[0].(map[string]any)
	handler := group["hooks"].([]any)[0].(map[string]any)
	return handler["commandWindows"].(string)
}
