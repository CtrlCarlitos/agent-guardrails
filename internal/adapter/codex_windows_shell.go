package adapter

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
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

const codexWindowsUnprovenShell = "guardrail: cannot prove the Windows command shell; refusing to emit a POSIX updatedInput rewrite and failing closed. Shell proof needs a readable transcript for this session under CODEX_HOME/sessions (default ~/.codex/sessions), recording powershell or pwsh. An explicit shell argument or a healthy doctor transport probe does not replace that evidence; report the missing session evidence to the operator and continue independent work."

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
		shell, diagnostic := tc.Shell, tc.ShellDiagnostic
		if shell == "" && diagnostic == "" {
			shell, diagnostic = codexCommandShell(tc.Raw)
		}
		if shell != engine.ShellPowerShell {
			reason := codexWindowsUnprovenShell + " Shell proof failed: " + diagnostic + "."
			fmt.Fprintln(stderr, reason)
			if codexStructuredWindowsEnabled() {
				return emitCodexBlock("pre", reason, stdout)
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
// interpreted. Codex's sandboxed PowerShell runs in ConstrainedLanguage, so
// the script uses only cmdlets and core-type members: a call such as
// [Console]::Error.WriteLine throws there and loses the guidance (#472).
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
		") { Write-Host 'guardrail: Codex workdir differs from the evaluated directory. Use the session working directory and an explicit Set-Location in the command so Guardrail can evaluate path changes.'; exit 1 }"
}

// windowsPathKey is the spelling PowerShell's ProviderPath is compared with:
// cleaned, backslashes, no trailing separator.
func windowsPathKey(p string) string {
	return strings.TrimRight(strings.ReplaceAll(filepath.Clean(p), "/", `\`), `\`)
}

// codexCommandShell is engine.ShellPowerShell when the session transcript
// proves Windows PowerShell or pwsh runs Codex's commands, and "" otherwise.
// ParseCodex records it on the call and the emit reuses it, so the
// transcript is read once per call (#498).
func codexCommandShell(raw []byte) (shell, diagnostic string) {
	shell, diagnostic = codexProvenShell(raw)
	switch shell {
	case "powershell", "pwsh":
		return engine.ShellPowerShell, ""
	}
	if diagnostic == "" {
		diagnostic = "recorded shell is unsupported (" + shell + ")"
	}
	return "", diagnostic
}

// codexProvenShell returns the shell recorded in the session transcript the
// hook payload points at, lower-cased, or "" when it cannot be established:
// an unusable reference with no uniquely session-bound replacement, a path
// outside Codex's sessions directory, an unreadable file, or no shell tag
// in its opening block.
func codexProvenShell(raw []byte) (shell, diagnostic string) {
	var p struct {
		TranscriptPath *string `json:"transcript_path"`
		SessionID      string  `json:"session_id"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return "", "invalid transcript_path in hook payload"
	}
	if p.TranscriptPath == nil || *p.TranscriptPath == "" {
		return recoverCodexSessionShell(p.SessionID, "no transcript_path")
	}
	path := filepath.Clean(*p.TranscriptPath)
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return "", "invalid transcript_path: expected an absolute .jsonl path"
	}
	if !withinCodexSessions(path) {
		return "", "transcript_path is outside CODEX_HOME/sessions"
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return recoverCodexSessionShell(p.SessionID, "transcript_path file is missing")
		}
		return "", "transcript_path file is unreadable"
	}
	defer f.Close()
	return readCodexTranscriptShell(f, "")
}

func readCodexTranscriptShell(f io.Reader, sessionID string) (shell, diagnostic string) {
	head, err := io.ReadAll(io.LimitReader(f, codexTranscriptScanBytes))
	if err != nil {
		return "", "transcript file is unreadable"
	}
	if sessionID != "" {
		var meta struct {
			Type    string `json:"type"`
			Payload struct {
				ID string `json:"id"`
			} `json:"payload"`
		}
		first, _, _ := strings.Cut(string(head), "\n")
		if json.Unmarshal([]byte(first), &meta) != nil || meta.Type != "session_meta" || meta.Payload.ID != sessionID {
			return "", "session id mismatch or missing session_meta identity"
		}
	}
	m := codexShellTag.FindSubmatch(head)
	if m == nil {
		return "", "no shell tag found in the transcript opening block"
	}
	return strings.ToLower(string(m[1])), ""
}

var codexSessionUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// codexSessionShell recovers a missing transcript reference, not missing proof.
// Only one regular rollout file inside the protected sessions tree may match
// the hook's UUID, and its first session_meta record must confirm that identity.
// A foreign explicit path never reaches this fallback. WalkDir does not follow
// symlinks; the entry and read bounds keep every hook invocation finite.
func recoverCodexSessionShell(sessionID, referenceProblem string) (shell, diagnostic string) {
	shell, diagnostic = codexSessionShell(sessionID)
	if diagnostic != "" {
		diagnostic = referenceProblem + "; session lookup: " + diagnostic
	}
	return shell, diagnostic
}

func codexSessionShell(sessionID string) (shell, diagnostic string) {
	if !codexSessionUUID.MatchString(sessionID) {
		return "", "missing or invalid session id"
	}
	root := codexSessionsRoot()
	if root == "" {
		return "", "cannot locate CODEX_HOME/sessions"
	}
	var match, walkProblem string
	entries := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		entries++
		if err != nil {
			return err
		}
		if entries > 10000 {
			walkProblem = "session directory scan limit reached"
			return fs.SkipAll
		}
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), "rollout-") || !strings.HasSuffix(entry.Name(), "-"+sessionID+".jsonl") {
			return nil
		}
		if match != "" {
			walkProblem = "multiple matching transcripts"
			return fs.SkipAll
		}
		match = path
		return nil
	})
	if err != nil {
		if os.IsNotExist(err) {
			return "", "session directory or rollout file is missing"
		}
		return "", "session directory is unreadable"
	}
	if walkProblem != "" {
		return "", walkProblem
	}
	if match == "" {
		return "", "no matching transcript"
	}
	f, err := os.Open(match)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "matching transcript file is missing"
		}
		return "", "matching transcript file is unreadable"
	}
	defer f.Close()
	return readCodexTranscriptShell(f, sessionID)
}

// codexSessionsRoot is the absolute sessions directory of the active Codex home.
func codexSessionsRoot() string {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		home = filepath.Join(userHome, ".codex")
	}
	if !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Clean(filepath.Join(home, "sessions"))
}

func withinCodexSessions(path string) bool {
	root := codexSessionsRoot()
	if root == "" {
		return false
	}
	root += string(filepath.Separator)
	if filepath.Separator == '\\' {
		return strings.HasPrefix(strings.ToLower(path), strings.ToLower(root))
	}
	return strings.HasPrefix(path, root)
}
