package delivery

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/pathutil"
)

func git(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	argv := []string{"--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=", "-C", dir}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, "git", argv...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "GIT_") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	out := &limitedBuffer{left: 8 << 20}
	cmd.Stdout = out
	cmd.Stderr = &limitedBuffer{left: 64 << 10}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Git %s failed: %w", args[0], err)
	}
	if out.failed {
		return "", fmt.Errorf("Git response exceeded verification budget")
	}
	return out.String(), nil
}

// CommonRoot makes one authorization cover linked task worktrees of the same
// non-bare repository, while preserving physical-path repository scoping.
func CommonRoot(ctx context.Context, cwd string) (string, error) {
	raw, err := git(ctx, cwd, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", err
	}
	common, err := pathutil.ResolveExisting(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if filepath.Base(common) != ".git" {
		return "", fmt.Errorf("delivery requires an ordinary non-bare Git repository")
	}
	return filepath.Dir(common), nil
}
