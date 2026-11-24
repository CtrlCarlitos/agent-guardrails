package delivery

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/gofrs/flock"
)

type registeredWorktree struct {
	path, head, branch string
	locked             bool
}

func registered(ctx context.Context, root string) ([]registeredWorktree, error) {
	raw, err := git(ctx, root, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return nil, err
	}
	var list []registeredWorktree
	for _, field := range strings.Split(raw, "\x00") {
		if strings.HasPrefix(field, "worktree ") {
			list = append(list, registeredWorktree{path: strings.TrimPrefix(field, "worktree ")})
			continue
		}
		if len(list) == 0 {
			continue
		}
		w := &list[len(list)-1]
		if strings.HasPrefix(field, "HEAD ") {
			w.head = strings.TrimPrefix(field, "HEAD ")
		}
		if strings.HasPrefix(field, "branch ") {
			w.branch = strings.TrimPrefix(field, "branch ")
		}
		if field == "locked" || strings.HasPrefix(field, "locked ") || strings.HasPrefix(field, "prunable") {
			w.locked = true
		}
	}
	return list, nil
}

func taskTip(ctx context.Context, root, ref string) (string, error) {
	raw, err := git(ctx, root, "for-each-ref", "--format=%(refname)%00%(objectname)%00%(symref)", "refs/heads/")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(raw, "\n") {
		v := strings.Split(line, "\x00")
		if len(v) == 3 && v[0] == ref {
			if v[2] != "" || !ValidOID(v[1]) {
				return "", fmt.Errorf("invalid or symbolic task ref")
			}
			return v[1], nil
		}
	}
	return "", nil
}

func pristine(ctx context.Context, path string, gitOptions ...string) error {
	index, err := git(ctx, path, "ls-files", "-v", "-z")
	if err != nil {
		return err
	}
	for _, entry := range strings.Split(index, "\x00") {
		if entry != "" && (entry[0] == 'S' || entry[0] >= 'a' && entry[0] <= 'z') {
			return fmt.Errorf("sparse or assume-unchanged index is unsupported")
		}
	}
	index, err = git(ctx, path, "ls-files", "--stage", "-z")
	if err != nil {
		return err
	}
	for _, entry := range strings.Split(index, "\x00") {
		if strings.HasPrefix(entry, "160000 ") {
			return fmt.Errorf("submodule cleanup is unsupported")
		}
	}
	status, err := git(ctx, path, append(gitOptions, "status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none")...)
	if err != nil {
		return err
	}
	if status != "" {
		return fmt.Errorf("task worktree has modified, untracked or ignored files")
	}
	return nil
}

// VerifyPublishedWorktree checks the evidence available locally. Remote-tracking
// refs record the last observed remote state and do not require a network call.
func VerifyPublishedWorktree(ctx context.Context, path string) error {
	root, err := git(ctx, path, "rev-parse", "--show-toplevel")
	if err != nil {
		return fmt.Errorf("cannot verify the worktree root")
	}
	rootInfo, rootErr := os.Stat(strings.TrimSuffix(root, "\n"))
	pathInfo, pathErr := os.Stat(path)
	if rootErr != nil || pathErr != nil || !os.SameFile(rootInfo, pathInfo) {
		return fmt.Errorf("cannot verify the worktree root")
	}
	refs, err := git(ctx, path, "for-each-ref", "--contains=HEAD", "--count=1", "--format=%(refname)", "refs/remotes/")
	if err != nil || strings.TrimSpace(refs) == "" {
		return fmt.Errorf("worktree HEAD has no remote-tracking ref")
	}
	keys, err := git(ctx, path, "config", "--null", "--name-only", "--list")
	if err != nil {
		return fmt.Errorf("cannot verify worktree Git configuration")
	}
	// The hook must not start external clean filters while inspecting files.
	var options []string
	for _, key := range strings.Split(keys, "\x00") {
		if strings.HasPrefix(key, "filter.") && (strings.HasSuffix(key, ".clean") || strings.HasSuffix(key, ".process")) {
			options = append(options, "-c", key+"=")
		}
	}
	return pristine(ctx, path, options...)
}

// Cleanup owns validation and deletion. It never grants direct Git commands,
// and never retries a failed non-force removal with force.
func Cleanup(ctx context.Context, api API, p policy.DeliveryPolicy, pr PullRequest, root, target string, before func() error) error {
	if pr.Head.Ref == "" || strings.EqualFold(pr.Head.Ref, p.Base) {
		return fmt.Errorf("default or unidentified branch cannot be cleaned")
	}
	ref := "refs/heads/" + pr.Head.Ref
	if _, err := git(ctx, root, "check-ref-format", ref); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(root, ".git", "guardrail-delivery.lock"), flock.SetPermissions(0o600))
	ok, err := lock.TryLockContext(ctx, 2*time.Second)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("delivery cleanup is already running")
	}
	defer lock.Unlock()
	_, live, err := ReadPR(ctx, api, p, pr.Number)
	if err != nil {
		return err
	}
	if !live.Merged || live.Head.SHA != pr.Head.SHA || live.MergeCommit != pr.MergeCommit {
		return fmt.Errorf("merged PR changed")
	}
	// GitHub's delete-on-merge owns remote deletion. The refs API has no
	// expected-old-OID delete, so never race a new push with a blind DELETE.
	var remote *[]struct {
		Ref string `json:"ref"`
	}
	if err := read(ctx, api, "repos/"+p.GitHub+"/git/matching-refs/heads/"+url.PathEscape(pr.Head.Ref), &remote); err != nil {
		return err
	}
	if remote == nil {
		return fmt.Errorf("remote branch inventory is unavailable")
	}
	for _, item := range *remote {
		if item.Ref == ref {
			return fmt.Errorf("remote task branch remains; enable GitHub delete-on-merge or have the operator review remote cleanup")
		}
	}
	tip, err := taskTip(ctx, root, ref)
	if err != nil {
		return err
	}
	if tip == "" {
		if target != "" {
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				return fmt.Errorf("task worktree still exists without its branch")
			}
		}
		return nil
	}
	if _, err := Redundancy(ctx, api, p, live, tip); err != nil {
		return err
	}
	chosen := ""
	if target != "" {
		if !filepath.IsAbs(target) {
			return fmt.Errorf("task worktree must be an absolute path")
		}
		info, err := os.Lstat(target)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink worktree root cannot be cleaned")
		}
		chosen, err = pathutil.ResolveExisting(target)
		if err != nil {
			return err
		}
		if pathutil.Same(chosen, root) {
			return fmt.Errorf("primary worktree cannot be cleaned")
		}
	}
	validate := func() error {
		list, err := registered(ctx, root)
		if err != nil {
			return err
		}
		found := chosen == ""
		for _, w := range list {
			if w.branch != ref {
				continue
			}
			actual, err := pathutil.ResolveExisting(w.path)
			if err != nil {
				return err
			}
			if chosen == "" || !pathutil.Same(actual, chosen) || w.head != tip || w.locked {
				return fmt.Errorf("task branch is attached elsewhere, moved or locked")
			}
			if err := pristine(ctx, chosen); err != nil {
				return err
			}
			found = true
		}
		if !found {
			return fmt.Errorf("path is not the task's registered worktree")
		}
		current, err := taskTip(ctx, root, ref)
		if err != nil {
			return err
		}
		if current != tip {
			return fmt.Errorf("task branch moved")
		}
		return nil
	}
	if err := validate(); err != nil {
		return err
	}
	if before == nil {
		return fmt.Errorf("cleanup requires live authorization and audit")
	}
	if err := before(); err != nil {
		return err
	}
	if err := validate(); err != nil {
		return err
	}
	if chosen != "" {
		if _, err := git(ctx, root, "worktree", "remove", "--", chosen); err != nil {
			return err
		}
	}
	// Compare-and-delete uses Git's ref lock. A concurrent new tip survives;
	// --no-deref prevents a symbolic-ref swap from targeting a different ref.
	_, err = git(ctx, root, "update-ref", "--no-deref", "-d", ref, tip)
	return err
}
