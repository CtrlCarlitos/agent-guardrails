package main

import (
	"encoding/json"
	"os"
	"runtime"
)

// codexSelftestProbes are the codex plane's probes, spelled for one host.
//
// Codex's adapter is the only one that demands a cwd which is both absolute
// and real — ADR-0016's fail-closed floor — so it is the only plane whose
// probes cannot carry a hardcoded `/tmp` everywhere. On Windows that string
// is a relative path, and both probes failed as unparseable payloads,
// reporting nothing about enforcement either way. os.TempDir is absolute and
// exists on every host, which is the whole requirement.
//
// The filesystem root is a second host-shaped value, for a different reason:
// containment is host-owned. `rm -rf /` destroys the machine on POSIX but is
// a cwd-relative delete on Windows, where `/` is not absolute. A probe that
// means "delete everything" has to say it in the host's spelling or it proves
// nothing. Both spellings are built on every host so their shape can be
// checked anywhere; only the running host's pair reaches the matrix.
func codexSelftestProbes(goos string) []selftestProbe {
	cwd, filesystemRoot := os.TempDir(), "/"
	if goos == "windows" {
		filesystemRoot = `C:\`
	}
	payload := func(command string) string {
		// Marshalled rather than written out, so the Windows separators are
		// escaped by the encoder instead of by hand.
		raw, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"session_id":      "selftest",
			"cwd":             cwd,
			"tool_name":       "Bash",
			"tool_input":      map[string]string{"command": command},
		})
		if err != nil {
			panic(err) // constant input; a failure here is a programming error
		}
		return string(raw)
	}
	return []selftestProbe{
		// Direct invocation proves the binary path and the verdicts; live
		// runtime mediation is a separate question (see audit records).
		{Plane: "codex", Name: "benign command allows", Args: []string{"codex"},
			Payload: payload("ls"), WantDecision: "allow"},
		{Plane: "codex", Name: "destructive denies", Args: []string{"codex"},
			Payload: payload("rm -rf " + filesystemRoot), WantDecision: "deny", WantRuleID: "P1.rm-rf"},
	}
}

func init() {
	selftestProbes = append(selftestProbes, codexSelftestProbes(runtime.GOOS)...)
}
