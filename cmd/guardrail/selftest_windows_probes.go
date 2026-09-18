package main

import "runtime"

// windowsSelftestProbes are the Claude probes a Windows host adds to the
// matrix: drive-lettered, backslash paths through the same adapter and
// Engine. They are appended only on Windows — path containment is
// host-owned, and a POSIX host would fail closed on `C:\repo` — but their
// shape is checked on every host.
func windowsSelftestProbes() []selftestProbe {
	return []selftestProbe{
		{Plane: "claude", Name: "windows secret read denies", Args: []string{"claude"},
			Payload:      `{"session_id":"selftest","cwd":"C:\\selftest","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"C:\\Users\\selftest\\.ssh\\id_ed25519"}}`,
			WantDecision: "deny", WantRuleID: "P4.secret-path"},
		{Plane: "claude", Name: "windows benign edit allows", Args: []string{"claude"},
			Payload:      `{"session_id":"selftest","cwd":"C:\\selftest","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"C:\\selftest\\a.go","old_string":"a","new_string":"b"}}`,
			WantDecision: "allow"},
		{Plane: "claude", Name: "windows rm -rf drive denies", Args: []string{"claude"},
			Payload:      `{"session_id":"selftest","cwd":"C:\\selftest","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf C:\\"}}`,
			WantDecision: "deny", WantRuleID: "P1.rm-rf"},
		{Plane: "claude", Name: "windows multiedit secret denies", Args: []string{"claude"},
			Payload:      `{"session_id":"selftest","cwd":"C:\\selftest","hook_event_name":"PreToolUse","tool_name":"MultiEdit","tool_input":{"file_path":"C:\\selftest\\a.go","edits":[{"file_path":"C:\\Users\\selftest\\.ssh\\id_ed25519","old_string":"c","new_string":"d"}]}}`,
			WantDecision: "deny", WantRuleID: "P4.secret-path"},
	}
}

func init() {
	if runtime.GOOS == "windows" {
		selftestProbes = append(selftestProbes, windowsSelftestProbes()...)
	}
}
