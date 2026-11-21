package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func initTestGitRepo(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "init", "-q", dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v (%s)", dir, err, out)
	}
	return dir
}

func runAntigravityPreHook(t *testing.T, sessionID, cwd, toolName string, args map[string]any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"conversationId": sessionID,
		"workspacePaths": []string{cwd},
		"toolCall": map[string]any{
			"name": toolName,
			"args": args,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out, errb strings.Builder
	code := run([]string{"hook", "antigravity", "pre"}, strings.NewReader(string(payload)), &out, &errb)
	if code != 0 {
		t.Fatalf("hook exit = %d, stderr = %q", code, errb.String())
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
		t.Fatalf("invalid hook JSON %q: %v", out.String(), err)
	}
	return resp
}

func TestHookNightModeRepoScopeIsolatesOtherReposAndPreservesExternalAsks(t *testing.T) {
	isolateNightConfig(t)
	testenv.SetState(t, t.TempDir())

	root := t.TempDir()
	repoA := initTestGitRepo(t, filepath.Join(root, "repo-a"))
	repoB := initTestGitRepo(t, filepath.Join(root, "repo-b"))

	code, stdout, stderr := runNightCommand(t, "on", "--scope", "repo", "--repo", repoA, "--for", "2h")
	if code != 0 {
		t.Fatalf("night on --scope repo exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "NIGHT MODE (repo ") {
		t.Fatalf("stdout = %q, want repo-scoped banner", stdout)
	}

	// Routine ask in repoA is relaxed to allow.
	inA := runAntigravityPreHook(t, "sess-1", repoA, "run_command", map[string]any{
		"CommandLine": "git push origin main",
		"Cwd":         repoA,
	})
	if inA["decision"] != "allow" {
		t.Fatalf("repoA routine ask = %+v, want allow under repo-scoped night mode", inA)
	}

	// Same routine ask in repoB stays force_ask (not relaxed).
	inB := runAntigravityPreHook(t, "sess-1", repoB, "run_command", map[string]any{
		"CommandLine": "git push origin main",
		"Cwd":         repoB,
	})
	if inB["decision"] != "force_ask" {
		t.Fatalf("repoB routine ask = %+v, want force_ask outside scoped repo", inB)
	}

	// External-tier ask in repoA MUST stay force_ask (ADR-0018).
	extA := runAntigravityPreHook(t, "sess-1", repoA, "schedule", map[string]any{
		"CronExpression": "*/5 * * * *",
		"Prompt":         "ping",
	})
	if extA["decision"] != "force_ask" {
		t.Fatalf("repoA external-tier ask = %+v, want force_ask (ADR-0018)", extA)
	}
}

func TestHookNightModeSessionScopeIsolatesOtherSessionsAndPreservesExternalAsks(t *testing.T) {
	isolateNightConfig(t)
	testenv.SetState(t, t.TempDir())

	repo := initTestGitRepo(t, filepath.Join(t.TempDir(), "repo"))

	code, stdout, stderr := runNightCommand(t, "on", "--scope", "session", "--session", "sess-overnight", "--for", "2h")
	if code != 0 {
		t.Fatalf("night on --scope session exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "NIGHT MODE (session sess-overnight)") {
		t.Fatalf("stdout = %q, want session-scoped banner", stdout)
	}

	// Matching session relaxes routine ask.
	inTarget := runAntigravityPreHook(t, "sess-overnight", repo, "run_command", map[string]any{
		"CommandLine": "git push origin main",
		"Cwd":         repo,
	})
	if inTarget["decision"] != "allow" {
		t.Fatalf("target session routine ask = %+v, want allow", inTarget)
	}

	// Different session in the SAME repo stays force_ask.
	inOther := runAntigravityPreHook(t, "sess-daytime", repo, "run_command", map[string]any{
		"CommandLine": "git push origin main",
		"Cwd":         repo,
	})
	if inOther["decision"] != "force_ask" {
		t.Fatalf("other session routine ask = %+v, want force_ask", inOther)
	}

	// External-tier ask in target session MUST stay force_ask (ADR-0018).
	extTarget := runAntigravityPreHook(t, "sess-overnight", repo, "schedule", map[string]any{
		"CronExpression": "*/5 * * * *",
		"Prompt":         "ping",
	})
	if extTarget["decision"] != "force_ask" {
		t.Fatalf("target session external-tier ask = %+v, want force_ask (ADR-0018)", extTarget)
	}
}

func TestNightOnScopedDefaultsAndValidation(t *testing.T) {
	t.Run("session scope falls back to GUARDRAIL_SESSION_ID", func(t *testing.T) {
		isolateNightConfig(t)
		t.Setenv("GUARDRAIL_SESSION_ID", "sess-from-env")
		code, stdout, stderr := runNightCommand(t, "on", "--scope", "session", "--for", "1h")
		if code != 0 {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
		if !strings.Contains(stdout, "session sess-from-env") {
			t.Fatalf("stdout = %q, want session sess-from-env", stdout)
		}
	})

	t.Run("repo scope resolves current git repo when --repo omitted", func(t *testing.T) {
		isolateNightConfig(t)
		repo := initTestGitRepo(t, filepath.Join(t.TempDir(), "cwd-repo"))
		t.Chdir(repo)
		code, stdout, stderr := runNightCommand(t, "on", "--scope", "repo", "--for", "1h")
		if code != 0 {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
		if !strings.Contains(stdout, "NIGHT MODE (repo ") {
			t.Fatalf("stdout = %q, want repo banner", stdout)
		}
	})

	t.Run("rejects invalid scope flag combinations", func(t *testing.T) {
		isolateNightConfig(t)
		t.Setenv("GUARDRAIL_SESSION_ID", "")
		repo := initTestGitRepo(t, filepath.Join(t.TempDir(), "bad-combo"))
		for _, args := range [][]string{
			{"on", "--scope", "cluster"},
			{"on", "--scope", "global", "--repo", repo},
			{"on", "--scope", "global", "--session", "s1"},
			{"on", "--scope", "repo", "--session", "s1"},
			{"on", "--scope", "session", "--repo", repo},
			{"on", "--scope", "session"},
			{"on", "--repo", repo},
			{"on", "--session", "s1"},
			{"on", "--scope", "repo", "--scope", "global"},
		} {
			code, _, stderr := runNightCommand(t, args...)
			if code != 2 {
				t.Errorf("%v: exit = %d, want 2 (stderr=%q)", args, code, stderr)
			}
		}
	})
}
