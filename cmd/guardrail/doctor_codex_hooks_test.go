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

func TestWindowsDoctorCodexHooksReportsIndependentStagesAndDecodedCommand(t *testing.T) {
	dir := t.TempDir()
	hooksPath := filepath.Join(dir, "hooks.json")
	commands := writeCodexDiagnosticConfig(t, hooksPath, `C:\Users\Agent User\.local\bin\guardrail.exe`)

	oldTrust, oldProbe, oldObservation := codexTrustInspector, codexHandlerProbe, codexRuntimeObserver
	t.Cleanup(func() {
		codexTrustInspector, codexHandlerProbe, codexRuntimeObserver = oldTrust, oldProbe, oldObservation
	})
	codexTrustInspector = func(context.Context, string) ([]codexTrustMetadata, error) {
		return []codexTrustMetadata{
			{EventName: "preToolUse", Command: commands["PreToolUse"], CurrentHash: "sha256:pre", TrustStatus: "trusted", SourcePath: hooksPath},
			{EventName: "postToolUse", Command: commands["PostToolUse"], CurrentHash: "sha256:post", TrustStatus: "trusted", SourcePath: hooksPath},
			{EventName: "sessionStart", Command: commands["SessionStart"], CurrentHash: "sha256:start", TrustStatus: "trusted", SourcePath: hooksPath},
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
		"$guardrailPath = 'C:\\Users\\Agent User\\.local\\bin\\guardrail.exe'",
		"$env:GUARDRAIL_CODEX_STRUCTURED_WINDOWS = '1'",
		"generated command hash: sha256:",
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
	commands := writeCodexDiagnosticConfig(t, hooksPath, `C:\guardrail.exe`)
	command := commands["PreToolUse"]

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

func writeCodexDiagnosticConfig(t *testing.T, hooksPath, binary string) map[string]string {
	t.Helper()
	fragment := genconfig.CodexConfig(binary)
	raw, err := json.Marshal(fragment)
	if err != nil {
		t.Fatal(err)
	}
	writePlaneSettings(t, hooksPath, string(raw))
	hooks := fragment["hooks"].(map[string]any)
	commands := map[string]string{}
	for _, event := range []string{"PreToolUse", "PostToolUse", "SessionStart"} {
		group := hooks[event].([]any)[0].(map[string]any)
		handler := group["hooks"].([]any)[0].(map[string]any)
		commands[event] = handler["commandWindows"].(string)
	}
	return commands
}
