package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
)

// ADR-0014: Codex omits the command's effective directory from hook input
// and reports the session cwd, so an allowed command goes back with a
// precondition that stops it when it runs anywhere else. On Windows the
// precondition must be written for the shell that will run it. Measured on
// Codex 0.159.0 (#454): the hook still receives tool_input {"command"} only,
// but the session transcript Codex hands the hook (transcript_path) records
// the shell in its environment block, <shell>powershell</shell>. That record
// is the proof: a PowerShell precondition is emitted only when it names
// PowerShell, and everything else keeps the fail-closed refusal.

const codexWindowsUnprovenShell = "guardrail: cannot prove the Windows command shell; refusing to emit a POSIX updatedInput rewrite and failing closed"

// codexTranscriptScanBytes bounds how much of a transcript is read: the
// environment block comes at the start of a session.
const codexTranscriptScanBytes = 1 << 20

var codexShellTag = regexp.MustCompile(`<shell>([A-Za-z0-9_.\-]{1,32})</shell>`)

// emitCodexAllowedCommand answers an allowed Codex command for the given OS:
// the original command behind a directory precondition, or, where the shell
// cannot be proven, the fail-closed refusal.
func emitCodexAllowedCommand(goos string, tc engine.ToolCall, stdout, stderr io.Writer) int {
	var command string
	if goos == "windows" {
		if shell := codexProvenShell(tc.Raw); shell != "powershell" && shell != "pwsh" {
			fmt.Fprintln(stderr, codexWindowsUnprovenShell)
			if codexStructuredWindowsEnabled() {
				return emitCodexBlock("pre", codexWindowsUnprovenShell, stdout)
			}
			return 2
		}
		command = powershellWorkdirPrecondition(tc.CWD) + "\n" + tc.Command
	} else {
		cwd, err := filepath.EvalSymlinks(tc.CWD)
		if err != nil {
			fmt.Fprintln(stderr, "guardrail: cannot verify Codex working directory; failing closed")
			return 2
		}
		quoted := "'" + strings.ReplaceAll(cwd, "'", "'\"'\"'") + "'"
		command = "if [ \"$(pwd -P)\" != " + quoted + " ]; then printf '%s\\n' 'guardrail: Codex workdir differs from the evaluated directory. Use the session working directory and an explicit cd in the command so Guardrail can evaluate path changes.' >&2; exit 1; fi\n" + tc.Command
	}
	payload := map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": map[string]any{"command": command}}}
	if err := json.NewEncoder(stdout).Encode(payload); err != nil {
		return 2
	}
	return 0
}

// powershellWorkdirPrecondition stops the command unless PowerShell's
// current directory is the evaluated one. It compares against the path as
// given and, when it resolves to something else, the resolved path. OneDrive's
// cloud-files folders are reparse points that may not resolve, or resolve to
// another spelling. PowerShell's -ne on strings ignores case, as Windows paths
// do. Paths are single-quoted with ' doubled, so nothing in them is
// interpreted.
func powershellWorkdirPrecondition(cwd string) string {
	candidates := []string{windowsPathKey(cwd)}
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		if key := windowsPathKey(resolved); !strings.EqualFold(key, candidates[0]) {
			candidates = append(candidates, key)
		}
	}
	conds := make([]string, 0, len(candidates))
	for _, c := range candidates {
		conds = append(conds, "$__guardrailCwd -ne '"+strings.ReplaceAll(c, "'", "''")+"'")
	}
	return "$__guardrailCwd = (Get-Location).ProviderPath.TrimEnd('\\'); if (" + strings.Join(conds, " -and ") +
		") { [Console]::Error.WriteLine('guardrail: Codex workdir differs from the evaluated directory. Use the session working directory and an explicit Set-Location in the command so Guardrail can evaluate path changes.'); exit 1 }"
}

// windowsPathKey is the spelling PowerShell's ProviderPath is compared with:
// cleaned, backslashes, no trailing separator.
func windowsPathKey(p string) string {
	return strings.TrimRight(strings.ReplaceAll(filepath.Clean(p), "/", `\`), `\`)
}

// codexProvenShell returns the shell recorded in the session transcript the
// hook payload points at, lower-cased, or "" when it cannot be established:
// no transcript_path, a path outside Codex's sessions directory, an
// unreadable file, or no shell tag in its opening block.
func codexProvenShell(raw []byte) string {
	var p struct {
		TranscriptPath *string `json:"transcript_path"`
	}
	if json.Unmarshal(raw, &p) != nil || p.TranscriptPath == nil || *p.TranscriptPath == "" {
		return ""
	}
	path := filepath.Clean(*p.TranscriptPath)
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".jsonl") || !withinCodexSessions(path) {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	head, err := io.ReadAll(io.LimitReader(f, codexTranscriptScanBytes))
	if err != nil {
		return ""
	}
	m := codexShellTag.FindSubmatch(head)
	if m == nil {
		return ""
	}
	return strings.ToLower(string(m[1]))
}

// withinCodexSessions reports whether path lies under the sessions
// directory of Codex's home ($CODEX_HOME, else ~/.codex), compared the way
// the platform compares paths.
func withinCodexSessions(path string) bool {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return false
		}
		home = filepath.Join(userHome, ".codex")
	}
	root := filepath.Clean(filepath.Join(home, "sessions")) + string(filepath.Separator)
	if filepath.Separator == '\\' {
		return strings.HasPrefix(strings.ToLower(path), strings.ToLower(root))
	}
	return strings.HasPrefix(path, root)
}
