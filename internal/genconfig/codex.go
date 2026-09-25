package genconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

const codexHookFailureSuffix = "; guardrail_status=$?; case \"$guardrail_status\" in 0) exit 0;; 2) exit 2;; 126|127) printf '%s\\n' \"guardrail: transport failure: configured handler executable is unavailable (exit $guardrail_status); continue independent work.\" >&2; exit 2;; *) printf '%s\\n' \"guardrail: handler failure: evaluator exited with code $guardrail_status; continue independent work.\" >&2; exit 2;; esac"
const codexWindowsHookPrefix = "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand "

func CodexConfig(binary string) Fragment {
	return CodexConfigFor("", binary)
}

func CodexConfigFor(hooksPath, binary string) Fragment {
	// Quote the executable as a shell word, including paths with spaces/apostrophes.
	quotedBinary := "'" + strings.ReplaceAll(binary, "'", "'\"'\"'") + "'"
	hooks := map[string]any{}
	for _, event := range []string{"PreToolUse", "PostToolUse", "SessionStart"} {
		handlerID := "guardrail-codex-" + event
		posixBase := quotedBinary + " hook codex --handler-id '" + handlerID + "'"
		command := posixBase + " --handler-hash '" + codexGeneratedCommandHash(posixBase) + "'" + codexHookFailureSuffix
		// Hash the generated invocation before adding its own hash argument. The
		// live diagnostic can therefore identify the exact generated variant,
		// while doctor separately reports Codex's trust hash for the full hook.
		var commandWindows string
		if hooksPath != "" {
			wrapperPath := filepath.Join(filepath.Dir(hooksPath), "guardrail-hook.cmd")
			// Codex runs commandWindows through the shell configured for the
			// session, which can be PowerShell or cmd.exe. Keep the entire outer
			// command free of quotes and shell-specific control operators; the
			// encoded script performs invocation and exit mapping in PowerShell.
			windowsBase := "& $wrapperPath --handler-id '" + handlerID + "'"
			windowsInvocation := "$payload | " + windowsBase + " --handler-hash '" + codexGeneratedCommandHash(windowsBase) + "'"
			windowsScript := codexWindowsHookScript("wrapperPath", wrapperPath, windowsInvocation, "configured handler wrapper is unavailable")
			commandWindows = codexWindowsHookPrefix + encodePowerShellCommand(windowsScript)
		} else {
			// Print-only fragments do not have an owned wrapper. Keep the direct
			// invocation inside the same shell-neutral encoded launcher.
			windowsBase := "& $guardrailPath hook codex --handler-id '" + handlerID + "'"
			windowsInvocation := "$payload | " + windowsBase + " --handler-hash '" + codexGeneratedCommandHash(windowsBase) + "'"
			windowsScript := codexWindowsHookScript("guardrailPath", binary, windowsInvocation, "configured handler executable is unavailable")
			commandWindows = codexWindowsHookPrefix + encodePowerShellCommand(windowsScript)
		}
		matcher := "*"
		if event == "PostToolUse" {
			matcher = "^apply_patch$"
		}
		hooks[event] = []any{map[string]any{
			"id": handlerID, "matcher": matcher,
			"hooks": []any{map[string]any{"type": "command", "command": command, "commandWindows": commandWindows, "timeout": 10}},
		}}
	}
	return Fragment{"hooks": hooks}
}

// codexWindowsHookScript keeps the outer command valid in both PowerShell and
// cmd.exe. PowerShell converts a nested native exit 2 into process exit 1 when
// it is itself run through -Command, so intentional blocking decisions are
// returned using Codex's documented event-specific JSON shapes with exit 0.
func codexWindowsHookScript(pathVariable, executablePath, invocation, unavailable string) string {
	quotedPath := strings.ReplaceAll(executablePath, "'", "''")
	block := "function Write-GuardrailBlock([string] $reason) { " +
		"if ([string]::IsNullOrWhiteSpace($reason)) { $reason = 'guardrail: handler failure: evaluator blocked without a reason; continue independent work.' } else { $reason = $reason.Trim() }; " +
		"try { $event = (ConvertFrom-Json -InputObject $payload).hook_event_name } catch { [Console]::Error.WriteLine($reason); exit 2 }; " +
		"if ($event -eq 'PreToolUse') { $response = @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'deny'; permissionDecisionReason = $reason } } } " +
		"elseif ($event -eq 'PostToolUse') { $response = @{ decision = 'block'; reason = $reason } } " +
		"elseif ($event -eq 'SessionStart') { $response = @{ continue = $false; stopReason = $reason; systemMessage = $reason } } " +
		"else { [Console]::Error.WriteLine($reason); exit 2 }; " +
		"[Console]::Out.Write(($response | ConvertTo-Json -Compress -Depth 4)); exit 0 }; "
	check := "if (-not (Test-Path -LiteralPath $" + pathVariable + " -PathType Leaf) -and $null -eq (Get-Command -Name $" + pathVariable + " -ErrorAction SilentlyContinue)) { Write-GuardrailBlock 'guardrail: transport failure: " + unavailable + "; continue independent work.' }; "
	run := "$stdoutPath = $null; $stderrPath = $null; try { " +
		"$stdoutPath = [IO.Path]::GetTempFileName(); $stderrPath = [IO.Path]::GetTempFileName(); " +
		invocation + " 1> $stdoutPath 2> $stderrPath; $guardrailExit = $LASTEXITCODE; " +
		"$guardrailOut = [IO.File]::ReadAllText($stdoutPath); $guardrailErr = [IO.File]::ReadAllText($stderrPath) " +
		"} catch { Write-GuardrailBlock ('guardrail: transport failure: PowerShell handler launcher failed (' + $_.Exception.Message + '); continue independent work.') } " +
		"finally { if ($null -ne $stdoutPath) { Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue }; if ($null -ne $stderrPath) { Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue } }; " +
		"if ($guardrailExit -eq 0) { [Console]::Out.Write($guardrailOut); [Console]::Error.Write($guardrailErr); exit 0 }; " +
		"if ([string]::IsNullOrWhiteSpace($guardrailErr)) { $guardrailErr = \"guardrail: handler failure: evaluator exited with code $guardrailExit; continue independent work.\" }; Write-GuardrailBlock $guardrailErr"
	return "$payload = [Console]::In.ReadToEnd(); " + block + "$" + pathVariable + " = '" + quotedPath + "'; " + check + run
}

// CodexWrapperContent returns the inspectable batch wrapper content for Codex
// hooks on Windows (ADR-0024).
func CodexWrapperContent(binary string) []byte {
	var b strings.Builder
	b.WriteString("@echo off\r\n")
	b.WriteString("@rem Generated by Guardrail. Inspectable hook wrapper (ADR-0024); see ADR-0004.\r\n")
	b.WriteString("\"" + strings.ReplaceAll(binary, "\"", "\\\"") + "\" hook codex %*\r\n")
	b.WriteString("@set \"guardrail_exit=%errorlevel%\"\r\n")
	b.WriteString("@if \"%guardrail_exit%\"==\"0\" exit /b 0\r\n")
	b.WriteString("@if \"%guardrail_exit%\"==\"2\" exit /b 2\r\n")
	b.WriteString("@echo guardrail: handler failure: evaluator exited with code %guardrail_exit%; continue independent work. 1>&2\r\n")
	b.WriteString("@exit /b 2\r\n")
	return []byte(b.String())
}

// WriteCodexWrapper writes the inspectable hook wrapper script alongside hooksPath.
func WriteCodexWrapper(hooksPath, binary string) error {
	dir := filepath.Dir(hooksPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "guardrail-hook.cmd")
	content := CodexWrapperContent(binary)
	if raw, err := os.ReadFile(path); err == nil && !bytes.Equal(raw, content) {
		if !strings.HasPrefix(string(raw), "@rem Generated by Guardrail.") && !strings.HasPrefix(string(raw), "@echo off\r\n@rem Generated by Guardrail.") {
			return fmt.Errorf("refusing to overwrite user-owned file: %s", path)
		}
	}
	return os.WriteFile(path, content, 0o700)
}

func codexGeneratedCommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return fmt.Sprintf("sha256:%x", sum)
}

func encodePowerShellCommand(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(raw[i*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func codexWindowsCommandHasHandler(command, handlerID string) bool {
	if script, ok := decodeCodexWindowsCommand(command); ok {
		return strings.Contains(script, "--handler-id '"+handlerID+"' --handler-hash 'sha256:")
	}
	return strings.Contains(command, "--handler-id "+handlerID+" --handler-hash sha256:")
}

func decodeCodexWindowsCommand(command string) (string, bool) {
	if !strings.HasPrefix(command, codexWindowsHookPrefix) {
		return "", false
	}
	fields := strings.Fields(strings.TrimPrefix(command, codexWindowsHookPrefix))
	if len(fields) != 1 {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil || len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[index*2:])
	}
	return string(utf16.Decode(units)), true
}

func codexWindowsCommandHasStructuredBlocks(command string) bool {
	script, ok := decodeCodexWindowsCommand(command)
	return ok && strings.Contains(script, "permissionDecision = 'deny'") &&
		strings.Contains(script, "decision = 'block'") &&
		strings.Contains(script, "continue = $false")
}

// CodexRules is a coarse native floor for command escalation, not a filesystem
// sandbox or a complete substitute for the Engine. See ADR-0016.
func CodexRules() []byte {
	var b strings.Builder
	b.WriteString("# Generated by Guardrail. Native escalation floor; see ADR-0016.\n")
	patterns := [][]string{
		{"dd"}, {"mkfs"}, {"wipefs"}, {"shred"}, {"srm"}, {"sudo"}, {"su"}, {"doas"},
		{"git", "reset", "--hard"}, {"git", "reset", "--keep"},
		{"git", "push", "--force"}, {"git", "push", "-f"},
		{"git", "clean", "-fd"}, {"git", "clean", "-df"},
		{"docker", "system", "prune"}, {"docker", "volume", "prune"},
	}
	for _, flags := range [][]string{{"-rf"}, {"-fr"}, {"-r", "-f"}, {"-f", "-r"}} {
		for _, target := range []string{"/", "~", ".", ".."} {
			pattern := append([]string{"rm"}, flags...)
			patterns = append(patterns, append(pattern, target))
		}
	}
	for _, pattern := range patterns {
		raw, _ := json.Marshal(pattern)
		fmt.Fprintf(&b, "prefix_rule(pattern = %s, decision = \"forbidden\", justification = \"Guardrail destructive-command floor; use a scoped reversible alternative.\")\n", raw)
	}
	return []byte(b.String())
}

// WriteCodexRules owns exactly one file. Refuse to replace a user-created file
// of the same name. Lifecycle disable keeps this floor, like Claude permissions.
func WriteCodexRules(hooksPath string) error {
	path := filepath.Join(filepath.Dir(hooksPath), "rules", "guardrail.rules")
	if raw, err := os.ReadFile(path); err == nil {
		if !strings.HasPrefix(string(raw), "# Generated by Guardrail.") {
			return fmt.Errorf("refusing to overwrite unowned Codex rules: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".guardrail-rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(CodexRules()); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// CodexHooksRegistered checks all required synchronous groups. Registration
// does not prove Codex's separate hook trust or feature settings.
func CodexHooksRegistered(doc map[string]any) bool {
	hooks, _ := doc["hooks"].(map[string]any)
	for _, event := range []string{"PreToolUse", "PostToolUse", "SessionStart"} {
		groups, _ := hooks[event].([]any)
		found := false
		for _, raw := range groups {
			group, _ := raw.(map[string]any)
			ownedID := "guardrail-codex-" + event
			if group["id"] != ownedID {
				continue
			}
			matcher, _ := group["matcher"].(string)
			if event != "PostToolUse" && matcher != "*" {
				continue
			}
			if event == "PostToolUse" && matcher != "^apply_patch$" {
				continue
			}
			handlers, _ := group["hooks"].([]any)
			for _, raw := range handlers {
				h, _ := raw.(map[string]any)
				command, _ := h["command"].(string)
				commandWindows, _ := h["commandWindows"].(string)
				isEncoded := strings.HasPrefix(commandWindows, codexWindowsHookPrefix)
				if h["type"] == "command" && h["async"] != true &&
					strings.Contains(command, " hook codex --handler-id '"+ownedID+"' --handler-hash 'sha256:") &&
					strings.HasSuffix(command, codexHookFailureSuffix) &&
					codexWindowsCommandHasHandler(commandWindows, ownedID) &&
					codexWindowsCommandHasStructuredBlocks(commandWindows) &&
					isEncoded {
					found = true
				}
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// CodexRulesRegistered also detects stale generated rules for reconciliation.
func CodexRulesRegistered(hooksPath string) bool {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(hooksPath), "rules", "guardrail.rules"))
	return err == nil && bytes.Equal(raw, CodexRules())
}
