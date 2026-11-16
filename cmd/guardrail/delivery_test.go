package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

func TestDeliveryStatusUnconfiguredDoesNotAuthorize(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	var out, stderr bytes.Buffer
	code := run([]string{"delivery", "status"}, strings.NewReader(""), &out, &stderr)
	if code != 0 || !strings.Contains(out.String(), "disabled") {
		t.Fatalf("status must report disabled without requesting approval: exit=%d out=%q err=%q", code, out.String(), stderr.String())
	}
}

func TestDeliveryFinishWithoutAuthorizationFailsClosed(t *testing.T) {
	testenv.SetConfig(t, t.TempDir())
	var out, stderr bytes.Buffer
	code := run([]string{"delivery", "finish", "--pr", "123"}, strings.NewReader(""), &out, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "not enabled") {
		t.Fatalf("unconfigured finish must name missing repository authorization: exit=%d out=%q err=%q", code, out.String(), stderr.String())
	}
}

// The live dotfiles acceptance run (dotfiles#502) exercised retry-after-cleanup-refusal
// on an already-merged PR: finish must SKIP the merge call, verify the recorded head
// against the confirmed merge, and proceed to cleanup — never re-merge. Nothing pinned
// that idempotency; this does. A refactor of the `!pr.Merged` skip in cmdDeliveryFinish
// would turn every resume into a second merge request (or a failure) with nothing red.
func TestDeliveryFinishOnMergedPRSkipsMergeAndVerifiesHead(t *testing.T) {
	mergeCommit := "fedcba9876543210fedcba9876543210fedcba98"
	recordedHead := "" // set once the sandbox task commit exists

	savedAPI := deliveryAPI
	t.Cleanup(func() { deliveryAPI = savedAPI })
	mergeCalled := false
	mergedPR := func() string {
		return `{"number":502,"state":"closed","merged":true,"merge_commit_sha":"` + mergeCommit + `",
		"head":{"ref":"task-502","sha":"` + recordedHead + `","repo":{"id":1366393295}},
		"base":{"ref":"main","sha":"` + mergeCommit + `","repo":{"id":1366393295}}}`
	}
	deliveryAPI = func(ctx context.Context, path string, body any, out any) error {
		switch {
		case strings.HasPrefix(path, "repos/owner/repo/pulls/502") && body == nil:
			return json.Unmarshal([]byte(mergedPR()), out)
		case strings.HasSuffix(path, "/merge"):
			mergeCalled = true
			return fmt.Errorf("merge must not be re-issued for an already-merged PR")
		case path == "repos/owner/repo":
			return json.Unmarshal([]byte(`{"id":1366393295,"full_name":"owner/repo","default_branch":"main"}`), out)
		case path == "repos/owner/repo/git/ref/heads/main":
			return json.Unmarshal([]byte(`{"object":{"sha":"`+mergeCommit+`","type":"commit"}}`), out)
		case strings.HasPrefix(path, "repos/owner/repo/compare/"):
			return json.Unmarshal([]byte(`{"status":"identical"}`), out)
		case path == "repos/owner/repo/git/matching-refs/heads/task-502":
			return json.Unmarshal([]byte(`[]`), out)
		}
		return fmt.Errorf("unexpected API path in test: %s", path)
	}

	// Sandbox: a git repo on main whose task branch is already contained in it,
	// so cleanup's redundancy proof and non-force local deletion succeed.
	repo := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main", ".")
	run("config", "user.email", "t@t")
	run("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "base")
	// The task branch: one real commit whose SHA becomes the recorded head.
	run("checkout", "-q", "-b", "task-502")
	if err := os.WriteFile(filepath.Join(repo, "task.txt"), []byte("t"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-qm", "task")
	headOut, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(headOut))
	recordedHead = head
	run("checkout", "-q", "main")
	branchRef := filepath.Join(repo, ".git", "refs", "heads")

	testenv.SetConfig(t, t.TempDir())
	stateRoot := t.TempDir()
	testenv.SetState(t, stateRoot)
	if err := os.MkdirAll(filepath.Dir(policy.OperatorConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	repoKey := strings.ReplaceAll(repo, "\\", "/")
	if err := os.WriteFile(policy.OperatorConfigPath(), []byte(fmt.Sprintf(
		"approval = 'prompt'\n\n[%q]\n  [%q.delivery]\n    github_id = 1366393295\n    github = 'owner/repo'\n    base = 'main'\n    method = 'squash'\n", repoKey, repoKey)), 0o600); err != nil {
		t.Fatal(err)
	}

	// finish resolves the repository root from the working directory.
	t.Chdir(repo)
	var finishOut, stderr bytes.Buffer
	code := cmdDelivery([]string{"finish", "--pr", "502", "--head", head}, false, nil, &finishOut, &stderr)
	if code != 0 {
		t.Fatalf("finish on merged PR must succeed without re-merging: exit=%d out=%q err=%q", code, finishOut.String(), stderr.String())
	}
	if mergeCalled {
		t.Fatal("finish re-issued the merge call for an already-merged PR")
	}
	if !strings.Contains(finishOut.String(), "merged as "+mergeCommit) {
		t.Fatalf("finish must confirm the recorded merge: %q", finishOut.String())
	}
	if _, err := os.Stat(filepath.Join(branchRef, "task-502")); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the redundant local branch")
	}
}
