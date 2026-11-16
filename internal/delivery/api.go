package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// CLIAPI uses gh's current credential without reading or printing credential
// files. The host is fixed; no agent-supplied hostname or raw API path enters it.
func CLIAPI(ctx context.Context, path string, body any, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	method := "GET"
	if body != nil {
		method = "PUT"
	}
	args := []string{"api", "--hostname", "github.com", "--method", method, path}
	var input []byte
	var err error
	if body != nil {
		input, err = json.Marshal(body)
		if err != nil {
			return err
		}
		args = append(args, "--input", "-")
	}
	cmd := exec.CommandContext(ctx, "gh", args...)
	if body != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	stdout := &limitedBuffer{left: 8 << 20}
	stderr := &limitedBuffer{left: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("GitHub API %s failed (check authentication, connectivity and server requirements): %w", method, err)
	}
	if stdout.failed || stderr.failed {
		return fmt.Errorf("GitHub API response exceeded verification budget")
	}
	if err := json.Unmarshal(stdout.Bytes(), out); err != nil {
		return fmt.Errorf("invalid GitHub API response: %w", err)
	}
	return nil
}

type limitedBuffer struct {
	bytes.Buffer
	left   int
	failed bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.left {
		b.failed = true
		return 0, io.ErrShortWrite
	}
	b.left -= len(p)
	return b.Buffer.Write(p)
}
