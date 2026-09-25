package genconfig

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/planecontract"
)

// antigravityHookCommand is HookCommand for a runtime that spawns hooks as
// `cmd /C <command>` through Go's exec, which escapes every embedded double
// quote as \". cmd.exe does not read that as a quote and looks for a program
// literally named `\"C:/…/guardrail.exe\"`, so the quoted spelling HookCommand
// emits for a Windows path denies every tool call (#353).
//
// A Windows path that needs no quoting is therefore emitted bare, forward
// slashes only. cmd.exe and a POSIX shell both take that spelling, so it
// keeps the property #149 bought. A path that does need quotes (a space, a
// metacharacter) falls back to HookCommand: unquoted it would be split, and
// no quote-free spelling exists for it.
func antigravityHookCommand(binary string, args ...string) string {
	if windowsShapedPath(binary) {
		slashed := strings.ReplaceAll(binary, `\`, "/")
		if bareWindowsWord(slashed) {
			return slashed + " " + strings.Join(args, " ")
		}
	}
	return HookCommand(binary, args...)
}

// bareWindowsWord reports whether a forward-slash Windows path reaches either
// shell untouched: the drive colon, then only what shellSafeWord admits, plus
// `~`. A shell expands `~` only at the start of a word, and this word starts
// with a drive letter or `/`, so an 8.3 short name (`RUNNER~1`) is literal.
func bareWindowsWord(p string) bool {
	rest := p
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		rest = p[2:]
	}
	return rest != "" && shellSafeWord("x"+strings.ReplaceAll(rest, "~", "x"))
}

// AntigravityConfig emits the proven named-wrapper shape from takumi-dream's
// working hooks.json: events live inside a "guardrail" key with "enabled"
// alongside. Antigravity has no declarative permission layer, so there is no
// permissions key.
func AntigravityConfig(binary string) Fragment {
	preCmd := antigravityHookCommand(binary, "hook", "antigravity", "pre")
	postCmd := antigravityHookCommand(binary, "hook", "antigravity", "post")
	return Fragment{
		"guardrail": map[string]any{
			"enabled": true,
			"PreToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-pre",
					"matcher": planecontract.AntigravityPreHookMatcher(),
					"hooks": []any{
						map[string]any{"type": "command", "command": preCmd, "timeout": 15},
					},
				},
			},
			"PostToolUse": []any{
				map[string]any{
					"id":      "guardrail-antigravity-post",
					"matcher": planecontract.AntigravityPostHookMatcher(),
					"hooks": []any{
						map[string]any{"type": "command", "command": postCmd, "timeout": 120},
					},
				},
			},
		},
	}
}
