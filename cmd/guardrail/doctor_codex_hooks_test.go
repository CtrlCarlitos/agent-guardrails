package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestDoctorCodexHooksReportsIndependentStagesAndDecodedCommand(t *testing.T) {
	dir := t.TempDir()
	hooksPath := filepath.Join(dir, "hooks.json")
	decoded := `& 'C:\Users\Agent User\.local\bin\guardrail.exe' hook codex; exit $LASTEXITCODE`
	encoded := encodeUTF16LEForTest(decoded)
	command := "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded + " || (echo guardrail: evaluator unavailable or blocked; continue independent work. 1>&2 & exit /b 2)"
	posixCommand := "'guardrail' hook codex || { printf '%s\\\\n' 'guardrail: evaluator unavailable or blocked; continue independent work.' >&2; exit 2; }"
	writePlaneSettings(t, hooksPath, `{"hooks":{`+
		`"PreToolUse":[{"id":"guardrail-codex-PreToolUse","matcher":"*","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}],`+
		`"PostToolUse":[{"id":"guardrail-codex-PostToolUse","matcher":"^apply_patch$","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}],`+
		`"SessionStart":[{"id":"guardrail-codex-SessionStart","matcher":"*","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}]}}`)

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
		return codexHandlerProbeResult{Started: true, ExitCode: 2, Stderr: "guardrail: malformed Codex hook payload; failing closed"}
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
		"decoded effective command: " + decoded,
		"trust hash: sha256:pre",
		"direct exit code: 2",
		"direct stderr: guardrail: malformed Codex hook payload; failing closed",
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
	decoded := `& 'C:\guardrail.exe' hook codex; exit $LASTEXITCODE`
	command := "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodeUTF16LEForTest(decoded) + " || (echo guardrail: evaluator unavailable or blocked; continue independent work. 1>&2 & exit /b 2)"
	posixCommand := "'guardrail' hook codex || { printf '%s\\\\n' 'guardrail: evaluator unavailable or blocked; continue independent work.' >&2; exit 2; }"
	writePlaneSettings(t, hooksPath, `{"hooks":{`+
		`"PreToolUse":[{"id":"guardrail-codex-PreToolUse","matcher":"*","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}],`+
		`"PostToolUse":[{"id":"guardrail-codex-PostToolUse","matcher":"^apply_patch$","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}],`+
		`"SessionStart":[{"id":"guardrail-codex-SessionStart","matcher":"*","hooks":[{"type":"command","command":"`+posixCommand+`","commandWindows":"`+command+`"}]}]}}`)

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

func encodeUTF16LEForTest(s string) string {
	units := utf16.Encode([]rune(s))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(raw)
}
