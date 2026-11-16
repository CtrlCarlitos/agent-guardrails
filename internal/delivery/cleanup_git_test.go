package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestWindowsDeliveryCleanupRealGit(t *testing.T) {
	for _, kind := range []string{"branch", "clean worktree", "dirty tracked", "untracked", "ignored", "assume unchanged", "moved ref", "audit failure", "remote branch"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			run := func(args ...string) string {
				t.Helper()
				out, err := git(ctx, root, args...)
				if err != nil {
					t.Fatal(err)
				}
				return strings.TrimSpace(out)
			}
			run("init", "-b", "main")
			run("config", "user.name", "Fixture")
			run("config", "user.email", "fixture@example.test")
			write := func(dir, name, value string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write(root, "value.txt", "base\n")
			write(root, ".gitignore", "ignored.txt\n")
			run("add", ".")
			run("-c", "commit.gpgsign=false", "commit", "-m", "fixture base")
			run("switch", "-c", "topic")
			write(root, "value.txt", "change\n")
			run("add", ".")
			run("-c", "commit.gpgsign=false", "commit", "-m", "fixture topic")
			head := run("rev-parse", "HEAD")
			headTree := run("rev-parse", "HEAD^{tree}")
			run("switch", "main")
			run("merge", "--squash", "topic")
			run("-c", "commit.gpgsign=false", "commit", "-m", "fixture squash")
			squash := run("rev-parse", "HEAD")
			base := run("rev-parse", "HEAD^")
			pr := PullRequest{Number: 7, State: "closed", Merged: true, MergeCommit: squash}
			pr.Head.SHA = head
			pr.Head.Ref = "topic"
			pr.Head.Repo.ID = 1
			pr.Base.Ref = "main"
			pr.Base.SHA = base
			pr.Base.Repo.ID = 1
			api := func(ctx context.Context, path string, body any, out any) error {
				var value any
				switch path {
				case "repos/o/r/git/matching-refs/heads/topic":
					value = []map[string]any{}
					if kind == "remote branch" {
						value = []map[string]any{{"ref": "refs/heads/topic", "object": map[string]string{"sha": head}}}
					}
				case "repos/o/r":
					value = Repository{ID: 1, FullName: "o/r", DefaultBranch: "main"}
				case "repos/o/r/pulls/7":
					value = pr
				case "repos/o/r/git/ref/heads/main":
					value = map[string]any{"object": map[string]string{"type": "commit", "sha": squash}}
				case "repos/o/r/compare/" + head + "..." + squash:
					value = map[string]string{"status": "diverged"}
				case "repos/o/r/compare/" + squash + "..." + squash:
					value = map[string]string{"status": "identical"}
				case "repos/o/r/git/commits/" + head:
					value = map[string]any{"sha": head, "tree": map[string]string{"sha": headTree}}
				case "repos/o/r/git/commits/" + squash:
					value = map[string]any{"sha": squash, "tree": map[string]string{"sha": headTree}, "parents": []map[string]string{{"sha": base}}}
				default:
					return fmt.Errorf("unexpected API path %s", path)
				}
				raw, err := json.Marshal(value)
				if err != nil {
					return err
				}
				return json.Unmarshal(raw, out)
			}
			target := ""
			if kind != "branch" && kind != "moved ref" && kind != "audit failure" && kind != "remote branch" {
				target = filepath.Join(t.TempDir(), "task")
				run("worktree", "add", target, "topic")
				if kind == "dirty tracked" || kind == "assume unchanged" {
					write(target, "value.txt", "valuable\n")
				}
				if kind == "untracked" {
					write(target, "notes.txt", "valuable\n")
				}
				if kind == "ignored" {
					write(target, "ignored.txt", "valuable\n")
				}
				if kind == "assume unchanged" {
					if _, err := git(ctx, target, "update-index", "--assume-unchanged", "value.txt"); err != nil {
						t.Fatal(err)
					}
				}
			}
			audited := false
			err := Cleanup(ctx, api, policy.DeliveryPolicy{GitHubID: 1, GitHub: "o/r", Base: "main", Method: "squash"}, pr, root, target, func() error {
				if kind == "audit failure" {
					return fmt.Errorf("audit unavailable")
				}
				audited = true
				if kind == "moved ref" {
					run("update-ref", "refs/heads/topic", squash)
				}
				return nil
			})
			clean := kind == "branch" || kind == "clean worktree"
			if clean {
				if err != nil || !audited {
					t.Fatalf("eligible cleanup failed: %v", err)
				}
				if out, _ := git(ctx, root, "show-ref", "--verify", "refs/heads/topic"); out != "" {
					t.Fatal("task branch remains")
				}
				if target != "" {
					if _, err := os.Stat(target); !os.IsNotExist(err) {
						t.Fatal("task worktree remains", err)
					}
				}
			} else {
				if err == nil {
					t.Fatal("unsafe cleanup was allowed")
				}
				if _, err := git(ctx, root, "show-ref", "--verify", "refs/heads/topic"); err != nil {
					t.Fatal("branch was lost", err)
				}
				if target != "" {
					if _, err := os.Stat(target); err != nil {
						t.Fatal("valuable worktree was lost", err)
					}
				}
			}
		})
	}
}
