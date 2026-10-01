package adapter

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #480: OpenCode's apply_patch carries its patch in `patchText` (OpenCode
// 1.18.33: patchText is "The full patch text that describes all changes to be
// made"). The adapter read `patch`, projected no paths, and every call failed
// closed with capability-input-missing.

func opencodeApplyPatch(t *testing.T, cwd string, args map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"session_id": "s1", "event": "pre", "tool": "apply_patch", "cwd": cwd, "arguments": args,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func patchText(lines ...string) string {
	return strings.Join(append(append([]string{"*** Begin Patch"}, lines...), "*** End Patch"), "\n")
}

func TestOpencodeApplyPatchProjectsPatchTextPaths(t *testing.T) {
	cwd := t.TempDir()
	rel := ".worktrees/ssh-agent-lf/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
	for name, tc := range map[string]struct {
		patch string
		want  []string
	}{
		// The exact call the dotfiles agent reported.
		"reported payload, workspace-relative": {
			patch: patchText("*** Update File: "+rel, "@@",
				"-        'doctor'    { & (Join-Path $repoScripts 'dotfiles-doctor.ps1') @rest }",
				"+        'doctor'    {",
				"+            $repair = @($rest | Where-Object { $_ -in '--fix', '-Fix' }).Count -gt 0",
				"+        }"),
			want: []string{filepath.Join(cwd, rel)},
		},
		"absolute path": {
			patch: patchText("*** Update File: "+filepath.Join(cwd, "a.txt"), "@@", "-x", "+y"),
			want:  []string{filepath.Join(cwd, "a.txt")},
		},
		"multiple files": {
			patch: patchText("*** Add File: new.txt", "+hi",
				"*** Update File: a.txt", "@@", "-x", "+y",
				"*** Delete File: old.txt"),
			want: []string{filepath.Join(cwd, "new.txt"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "old.txt")},
		},
		"move checks source and destination": {
			patch: patchText("*** Update File: a.txt", "*** Move to: sub/b.txt", "@@", "-x", "+y"),
			want:  []string{filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "sub", "b.txt")},
		},
		"CRLF line endings": {
			patch: strings.ReplaceAll(patchText("*** Update File: a.txt", "@@", "-x", "+y"), "\n", "\r\n"),
			want:  []string{filepath.Join(cwd, "a.txt")},
		},
	} {
		got, err := ParseOpencode(strings.NewReader(opencodeApplyPatch(t, cwd, map[string]any{"patchText": tc.patch})))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Capability != policy.CapabilityMutation || got.InputShape != "path" {
			t.Errorf("%s: capability %q shape %q, want mutation/path", name, got.Capability, got.InputShape)
		}
		if !reflect.DeepEqual(cleanAll(got.Paths), tc.want) {
			t.Errorf("%s: paths %q, want %q", name, got.Paths, tc.want)
		}
	}
}

func TestOpencodeApplyPatchMalformedFailsClosed(t *testing.T) {
	for name, args := range map[string]map[string]any{
		"no patchText":           {},
		"only the old patch key": {"patch": patchText("*** Update File: a.txt")},
		"empty patchText":        {"patchText": ""},
		"non-string patchText":   {"patchText": 42},
		"no envelope":            {"patchText": "*** Update File: a.txt\n@@\n-x\n+y"},
		"no file operations":     {"patchText": patchText("@@", "-x", "+y")},
		"empty path":             {"patchText": patchText("*** Update File: ", "@@")},
		"empty move destination": {"patchText": patchText("*** Update File: a.txt", "*** Move to: ")},
	} {
		if _, err := ParseOpencode(strings.NewReader(opencodeApplyPatch(t, "/work", args))); err == nil {
			t.Errorf("%s: parsed without error; want fail-closed", name)
		}
	}
}

func cleanAll(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Clean(p)
	}
	return out
}
