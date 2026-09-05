package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func gitInitSync(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.email", "t@t"}, {"config", "user.name", "t"}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func assertTerminalRecords(t *testing.T, output string, want int) []string {
	t.Helper()
	if !strings.HasSuffix(output, "\n") {
		t.Fatalf("terminal output does not end in a newline: %q", output)
	}
	records := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(records) != want {
		t.Fatalf("terminal output has %d records, want %d: %q", len(records), want, output)
	}
	for _, record := range records {
		if strings.IndexFunc(record, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			t.Fatalf("terminal record contains a control character: %q", record)
		}
	}
	return records
}

func TestSyncAllPlanes(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	overlay := "waive = [\"P6\"]\n"
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(overlay), 0o644)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	claudePath := filepath.Join(dir, ".claude", "settings.json")
	if _, err := os.Stat(claudePath); err != nil {
		t.Fatalf(".claude/settings.json not written: %v", err)
	}
	oc := filepath.Join(dir, "opencode.json")
	if _, err := os.Stat(oc); err != nil {
		t.Fatalf("opencode.json not written: %v", err)
	}
	pluginPath := filepath.Join(dir, ".guardrail", "guardrail.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("opencode plugin not deployed: %v", err)
	}
	ag := filepath.Join(dir, ".agents", "hooks.json")
	if _, err := os.Stat(ag); err != nil {
		t.Fatalf(".agents/hooks.json not written: %v", err)
	}

	raw, _ := os.ReadFile(ag)
	if !strings.Contains(string(raw), "guardrail-antigravity-pre") {
		t.Errorf("antigravity hooks.json missing the owned id")
	}
}

func TestSyncSinglePlane(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "/opt/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "opencode.json")); err == nil {
		t.Error("opencode.json should not have been written when --planes=claude")
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.json")); err != nil {
		t.Error(".claude/settings.json should have been written")
	}
}

func TestSyncOpencodeBakesAbsoluteBinary(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "/ABS/SENTINEL/guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "/ABS/SENTINEL/guardrail") {
		t.Fatalf("synced plugin does not pin the absolute binary path:\n%s", js)
	}
	if strings.Contains(string(js), "process.env.GUARDRAIL_BIN") {
		t.Error("plugin still resolves its enforcer from the environment")
	}
}

func TestSyncOpencodeResolvesBareBinaryFromPATH(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	binDir := t.TempDir()
	wantBinary := writePathExecutable(t, binDir, "guardrail-sentinel")
	t.Setenv("PATH", binDir)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "guardrail-sentinel"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	js, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), wantBinary) {
		t.Fatalf("synced plugin does not contain PATH-resolved binary %q:\n%s", wantBinary, js)
	}
}

func TestSyncMixedPlanesResolveBinaryOnlyForOpencode(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	binDir := filepath.Join(t.TempDir(), "bin with spaces;$(not-run)")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	wantBinary := writePathExecutable(t, binDir, "guardrail-sentinel")
	t.Setenv("PATH", binDir)

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude,opencode,antigravity", "--binary", "guardrail-sentinel"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}

	plugin, err := os.ReadFile(filepath.Join(dir, ".guardrail", "guardrail.js"))
	if err != nil {
		t.Fatal(err)
	}
	encodedBinary, err := json.Marshal(wantBinary)
	if err != nil {
		t.Fatal(err)
	}
	wantDeclaration := "const GUARDRAIL_BIN = " + string(encodedBinary) + ";"
	if !strings.Contains(string(plugin), wantDeclaration) {
		t.Fatalf("OpenCode plugin does not pin the exact PATH result %q:\n%s", wantBinary, plugin)
	}

	claudeRaw, err := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var claude map[string]any
	if err := json.Unmarshal(claudeRaw, &claude); err != nil {
		t.Fatal(err)
	}
	claudePre := claude["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	claudeCommand := claudePre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if claudeCommand != "guardrail-sentinel hook claude" {
		t.Fatalf("Claude command = %q, want original bare binary semantics", claudeCommand)
	}

	antigravityRaw, err := os.ReadFile(filepath.Join(dir, ".agents", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var antigravity map[string]any
	if err := json.Unmarshal(antigravityRaw, &antigravity); err != nil {
		t.Fatal(err)
	}
	guardrail := antigravity["guardrail"].(map[string]any)
	antigravityPre := guardrail["PreToolUse"].([]any)[0].(map[string]any)
	antigravityCommand := antigravityPre["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if antigravityCommand != "guardrail-sentinel hook antigravity pre" {
		t.Fatalf("Antigravity command = %q, want original bare binary semantics", antigravityCommand)
	}
}

func TestSyncMixedPlanesRejectUnresolvedBareBinaryBeforeDeployment(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	t.Setenv("PATH", t.TempDir())

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude,opencode,antigravity", "--binary", "missing-guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; stderr=%s", code, errb.String())
	}
	wantErr := "guardrail: sync: cannot resolve --binary: executable \"missing-guardrail\" not found in PATH\n"
	if errb.String() != wantErr {
		t.Fatalf("stderr = %q, want %q", errb.String(), wantErr)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
	for _, path := range []string{
		filepath.Join(dir, ".claude"),
		filepath.Join(dir, ".guardrail"),
		filepath.Join(dir, "opencode.json"),
		filepath.Join(dir, ".agents"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s was deployed on resolution failure: %v", path, err)
		}
	}
}

func TestSyncOverlayReachesClaudeFloor(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(`
[slots]
secret_globs = ["secrets/prod/**"]
`), 0o644)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, ".claude", "settings.json"))
	if !strings.Contains(string(raw), "Read(secrets/prod/**)") {
		t.Fatalf("overlay secret_globs did not reach the synced Claude floor:\n%s", raw)
	}
}

func TestSyncUsesTopLevelRepoGrantFromSubdirectory(t *testing.T) {
	_, sub := repoWithAuthorizedWaiver(t)
	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", sub, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "guardrail: rule P6.egress is WAIVED for this repo by operator authorization") {
		t.Fatalf("top-level operator grant was not applied from subdirectory: %s", errb.String())
	}
}

func TestSyncMergedRelativeSafeRootIsConsumedAsAbsolute(t *testing.T) {
	repoRoot := t.TempDir()
	overlayPath := filepath.Join(repoRoot, "guardrail.toml")
	if err := os.WriteFile(overlayPath, []byte("[slots]\nsafe_roots = [\"tmp\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ov, err := policy.LoadOverlay(overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	merged, warnings, err := policy.Merge(&policy.Policy{Waived: map[string]bool{}}, ov, "1.0.0", nil, repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	// Use a different RepoRoot so the Engine's implicit repository safety does
	// not mask whether the merged safe root uses absolute coordinates.
	target := filepath.Join(repoRoot, "tmp", "cache")
	otherRepo := filepath.Join(filepath.Dir(repoRoot), "other-repo")
	verdict := engine.Evaluate(engine.ToolCall{
		Tool:     "Bash",
		Command:  "rm -rf " + target,
		CWD:      otherRepo,
		RepoRoot: otherRepo,
	}, merged)
	if verdict.Decision != policy.Allow {
		t.Fatalf("absolute target under merged relative safe_root was not consumed as safe: %+v", verdict)
	}
}

func TestSyncSanitizesEveryMergeWarningWithoutCapping(t *testing.T) {
	dir := t.TempDir()
	gitInitSync(t, dir)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	egress := []string{`"evil\nforged\tentry\u007f"`, `"` + strings.Repeat("x", 250) + `"`}
	for i := range 20 {
		egress = append(egress, fmt.Sprintf("%q", fmt.Sprintf("host-%02d.example", i)))
	}
	overlay := `audit_log = "/outside/audit\nforged\tpath\u007f"
waive = ["P1.rm-rf\nforged\twaiver\u007f"]

[slots]
safe_roots = ["/outside/safe\nforged\troot\u007f"]
secret_allow = ["secret\nforged\tallow\u007f"]
egress_allowlist = [` + strings.Join(egress, ", ") + "]\n"
	if err := os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	records := assertTerminalRecords(t, errb.String(), 26)
	assertTerminalRecords(t, out.String(), 1)

	joined := strings.Join(records, "\n")
	if strings.Count(joined, "egress_allowlist entry") != len(egress) {
		t.Fatalf("egress warnings were lost or combined: %q", errb.String())
	}
	for _, marker := range []string{
		"safe forged root outside the repository",
		"evil forged entry",
		strings.Repeat("x", 250),
		"secret protection remains ENFORCED",
		"audit forged path",
		"the default audit path is retained",
		"P1.rm-rf forged waiver",
		"which is NOT authorized",
		"the rule remains ENFORCED",
	} {
		if !strings.Contains(joined, marker) {
			t.Errorf("sanitized warning output omitted %q: %q", marker, errb.String())
		}
	}
	for i := range 20 {
		if marker := fmt.Sprintf("host-%02d.example", i); !strings.Contains(joined, marker) {
			t.Errorf("sanitized warning output omitted %q", marker)
		}
	}
}

func TestSyncSanitizesWarningCallbackAndSuccessfulTargetPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "repo\nsynced opencode -> forged\t\x1b[31m\x7f")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInitSync(t, dir)
	t.Setenv("GUARDRAIL_CONFIG", filepath.Join(dir, "missing\nsynced antigravity -> forged\t\x1b[32m\x7f.toml"))

	var out, errb bytes.Buffer
	code := run([]string{"sync", "--dir", dir, "--planes", "claude", "--binary", "guardrail"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, errb.String())
	}
	outRecords := assertTerminalRecords(t, out.String(), 1)
	errRecords := assertTerminalRecords(t, errb.String(), 1)
	if !strings.HasPrefix(outRecords[0], "synced claude -> ") {
		t.Fatalf("successful target forged a sync status: %q", out.String())
	}
	if !strings.Contains(errRecords[0], "missing synced antigravity -> forged [32m .toml") {
		t.Fatalf("overlay lookup warning path was not sanitized: %q", errb.String())
	}
}

func TestSyncSanitizesEverySuccessfulTargetPath(t *testing.T) {
	for _, plane := range []string{"claude", "opencode", "antigravity"} {
		t.Run(plane, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "repo\nsynced forged\t\x1b[31m\x7f")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			var out, errb bytes.Buffer
			syncPlane(plane, dir, "/opt/guardrail", &policy.Policy{Waived: map[string]bool{}}, &out, &errb)
			records := assertTerminalRecords(t, out.String(), 1)
			if !strings.HasPrefix(records[0], "synced "+plane+" -> ") {
				t.Fatalf("status prefix was altered: %q", out.String())
			}
			if errb.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", errb.String())
			}
		})
	}
}

func TestSyncSanitizesSyncPlaneErrorsAndUnknownName(t *testing.T) {
	for _, tt := range []struct {
		plane   string
		blocker string
	}{
		{plane: "claude", blocker: ".claude"},
		{plane: "opencode", blocker: ".guardrail"},
		{plane: "antigravity", blocker: ".agents"},
	} {
		t.Run(tt.plane, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "repo\nforged status\t\x1b[31m\x7f")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, tt.blocker), []byte("block"), 0o644); err != nil {
				t.Fatal(err)
			}

			var out, errb bytes.Buffer
			syncPlane(tt.plane, dir, "guardrail", &policy.Policy{Waived: map[string]bool{}}, &out, &errb)
			records := assertTerminalRecords(t, errb.String(), 1)
			if !strings.HasPrefix(records[0], "guardrail: sync "+tt.plane+" failed: ") {
				t.Fatalf("error prefix was altered: %q", errb.String())
			}
			if out.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", out.String())
			}
		})
	}

	var out, errb bytes.Buffer
	syncPlane("evil\nsynced forged\t\x1b[31m\x7f", t.TempDir(), "guardrail", &policy.Policy{}, &out, &errb)
	records := assertTerminalRecords(t, errb.String(), 1)
	if records[0] != `guardrail: sync: unknown plane "evil synced forged [31m", skipping` {
		t.Fatalf("unknown plane diagnostic = %q", errb.String())
	}
}

func TestSyncSanitizesResolvedBinaryAndFlagParserErrors(t *testing.T) {
	t.Run("resolved binary", func(t *testing.T) {
		dir := t.TempDir()
		gitInitSync(t, dir)
		t.Setenv("PATH", t.TempDir())

		var out, errb bytes.Buffer
		code := run([]string{"sync", "--dir", dir, "--planes", "opencode", "--binary", "missing\nsynced forged\t\x1b[31m\x7f"}, strings.NewReader(""), &out, &errb)
		if code != 2 {
			t.Fatalf("exit=%d, want 2", code)
		}
		records := assertTerminalRecords(t, errb.String(), 1)
		if !strings.HasPrefix(records[0], "guardrail: sync: cannot resolve --binary: ") {
			t.Fatalf("binary error prefix was altered: %q", errb.String())
		}
	})

	t.Run("flag parser", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run([]string{"sync", "--unknown\nsynced forged\t\x1b[31m\x7f"}, strings.NewReader(""), &out, &errb)
		if code != 2 {
			t.Fatalf("exit=%d, want 2", code)
		}
		records := assertTerminalRecords(t, errb.String(), 1)
		if !strings.HasPrefix(records[0], "flag provided but not defined: ") {
			t.Fatalf("flag error prefix was altered: %q", errb.String())
		}
	})
}

func TestSyncSanitizesInvalidOverlayAndOperatorConfigErrors(t *testing.T) {
	t.Run("invalid merged overlay", func(t *testing.T) {
		dir := t.TempDir()
		gitInitSync(t, dir)
		overlay := `[[rules]]
id = "evil\nsynced forged\tname\u007f"
pattern = "*"
decision = "allow\tforged\u007f"
`
		if err := os.WriteFile(filepath.Join(dir, "guardrail.toml"), []byte(overlay), 0o644); err != nil {
			t.Fatal(err)
		}

		var out, errb bytes.Buffer
		code := run([]string{"sync", "--dir", dir, "--planes", "claude"}, strings.NewReader(""), &out, &errb)
		if code != 2 {
			t.Fatalf("exit=%d, want 2", code)
		}
		records := assertTerminalRecords(t, errb.String(), 1)
		if !strings.HasPrefix(records[0], "guardrail: sync: invalid overlay: ") {
			t.Fatalf("overlay error prefix was altered: %q", errb.String())
		}
	})

	t.Run("operator config", func(t *testing.T) {
		dir := t.TempDir()
		gitInitSync(t, dir)
		configHome := filepath.Join(t.TempDir(), "config\nsynced forged\t\x1b[31m\x7f")
		configDir := filepath.Join(configHome, "guardrail")
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(configDir, "waivers.toml"), []byte("invalid = ["), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", configHome)

		var out, errb bytes.Buffer
		code := run([]string{"sync", "--dir", dir, "--planes", "claude"}, strings.NewReader(""), &out, &errb)
		if code != 0 {
			t.Fatalf("exit=%d stderr=%q", code, errb.String())
		}
		records := assertTerminalRecords(t, errb.String(), 1)
		if !strings.HasPrefix(records[0], "guardrail: operator config unreadable (") ||
			!strings.HasSuffix(records[0], "); treating as empty") {
			t.Fatalf("operator error disposition was altered: %q", errb.String())
		}
		assertTerminalRecords(t, out.String(), 1)
	})
}
