package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// agySpawnBudget bounds one probe. `version` returns at once; the budget only
// matters when the spawn hangs.
const agySpawnBudget = 5 * time.Second

// agySpawn reaches an executable the way Antigravity's runtime spawns a hook
// on Windows: `cmd /C <command>` through Go's exec, which escapes every
// embedded quote as \". That is the mechanism that made a quoted binary path
// unspawnable (#353). It runs `version`, which writes no audit record, and is
// a no-op elsewhere, where agy's spawn is not known to mangle quotes.
func agySpawn(exe string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), agySpawnBudget)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cmd", "/C", exe+" version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// antigravityHookSpawnProblems probes every guardrail-owned command in the
// parsed hooks.json with spawn and returns one operator-facing line per
// command that cannot be reached. doctor otherwise only reads the file: a
// floor whose command registers fine and cannot spawn reports healthy while
// the plane denies every tool call, the exact fail-closed lockout of #353.
func antigravityHookSpawnProblems(doc map[string]any, spawn func(exe string) error) []string {
	guardrail, _ := doc["guardrail"].(map[string]any)
	events := make([]string, 0, len(guardrail))
	for event := range guardrail {
		events = append(events, event)
	}
	sort.Strings(events)
	var problems []string
	for _, event := range events {
		groups, _ := guardrail[event].([]any)
		for _, raw := range groups {
			group, _ := raw.(map[string]any)
			id, _ := group["id"].(string)
			if !strings.HasPrefix(id, "guardrail-") {
				continue
			}
			handlers, _ := group["hooks"].([]any)
			for _, h := range handlers {
				handler, _ := h.(map[string]any)
				command, _ := handler["command"].(string)
				exe := leadingCommandWord(command)
				if exe == "" {
					continue
				}
				if err := spawn(exe); err != nil {
					problems = append(problems, fmt.Sprintf(
						"hook %s cannot spawn under Antigravity's `cmd /C` (%s): %s. Every Antigravity tool call is denied until it can. `guardrail plane enable antigravity` rewrites the command; a binary path containing a space cannot be written without quotes, so install to a path without one (an 8.3 short path such as C:/PROGRA~1 also works) (#353)",
						id, exe, strings.TrimRight(err.Error(), ". ")))
				}
			}
		}
	}
	return problems
}

// leadingCommandWord is the command's executable text as written: the quoted
// span when it opens with a quote, otherwise the text up to the first space.
func leadingCommandWord(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if q := command[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(command[1:], q); end >= 0 {
			return command[:end+2]
		}
		return command
	}
	if i := strings.IndexByte(command, ' '); i >= 0 {
		return command[:i]
	}
	return command
}

// antigravityHookSpawner is what doctor probes with; a variable so a test can
// stand in on a host where agySpawn is a no-op.
var antigravityHookSpawner = agySpawn
