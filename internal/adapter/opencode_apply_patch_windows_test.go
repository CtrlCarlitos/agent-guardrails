package adapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #480: on Windows a drive-less rooted path (`\Users\me\.ssh\id_ed25519`)
// names a file on the current drive. Joined to the cwd it would read as an
// in-repo file and pass; the Engine must see it as written and deny it.
func TestWindowsApplyPatchRootedPathReachesTheEngineUnjoined(t *testing.T) {
	pol, err := policy.LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	rooted := home[len(filepath.VolumeName(home)):]
	cwd := t.TempDir()
	for _, target := range []string{
		filepath.Join(rooted, ".ssh", "id_ed25519"),
		filepath.Join(rooted, "AppData", "Roaming", "guardrail", "waivers.toml"),
	} {
		for _, spelled := range []string{target, filepath.ToSlash(target)} {
			patch := patchText("*** Update File: a.txt", "*** Move to: "+spelled, "@@", "-x", "+y")
			opencode, err := ParseOpencode(strings.NewReader(opencodeApplyPatch(t, cwd, map[string]any{"patchText": patch})))
			if err != nil {
				t.Fatal(err)
			}
			codexRaw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s", "cwd": cwd, "tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}})
			codex, err := ParseCodex(strings.NewReader(string(codexRaw)))
			if err != nil {
				t.Fatal(err)
			}
			for plane, tc := range map[string]engine.ToolCall{"opencode": opencode, "codex": codex} {
				if got := tc.Paths[len(tc.Paths)-1]; got != spelled {
					t.Errorf("%s %s: move destination projected as %q; want it unjoined", plane, spelled, got)
				}
				tc.RepoRoot = cwd
				if v := engine.Evaluate(tc, pol); v.Decision != policy.Deny {
					t.Errorf("%s %s: %s %s; want deny", plane, spelled, v.Decision, v.RuleID)
				}
			}
		}
	}
}

// #480: the reported Windows absolute path, in OpenCode's backslash form and
// in forward slashes, is kept as that file rather than joined to the cwd.
func TestWindowsOpencodeApplyPatchAbsolutePath(t *testing.T) {
	const want = `C:\Users\carlitos\.local\share\chezmoi\.worktrees\ssh-agent-lf\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`
	for _, spelled := range []string{want, filepath.ToSlash(want)} {
		raw := opencodeApplyPatch(t, `C:\Users\carlitos\.local\share\chezmoi`, map[string]any{
			"patchText": patchText("*** Update File: "+spelled, "@@", "-x", "+y"),
		})
		got, err := ParseOpencode(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", spelled, err)
		}
		if !reflect.DeepEqual(cleanAll(got.Paths), []string{want}) {
			t.Errorf("%s: paths %q, want %q", spelled, got.Paths, want)
		}
	}
}
