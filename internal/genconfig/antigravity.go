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
// metacharacter) is written as its 8.3 short name when the volume has one and
// that name is itself quote-free (#358). With none, it falls back to
// HookCommand: unquoted the path would be split, and no quote-free spelling
// exists for it, which doctor reports.
func antigravityHookCommand(binary string, args ...string) string {
	if word, ok := antigravityBareWord(binary); ok {
		return word + " " + strings.Join(args, " ")
	}
	return HookCommand(binary, args...)
}

// antigravityBareWord is the quote-free spelling of a Windows binary path, or
// false when there is none.
func antigravityBareWord(binary string) (string, bool) {
	if !windowsShapedPath(binary) {
		return "", false
	}
	if slashed := strings.ReplaceAll(binary, `\`, "/"); bareWindowsWord(slashed) {
		return slashed, true
	}
	short, ok := shortPathResolver(binary)
	if !ok {
		return "", false
	}
	// With 8.3 creation off GetShortPathName returns the long name unchanged;
	// only a result that really is quote-free counts.
	if slashed := strings.ReplaceAll(short, `\`, "/"); bareWindowsWord(slashed) {
		return slashed, true
	}
	return "", false
}

// AntigravityHookSpawnable reports whether agy can spawn a hook for this
// binary path. Only a Windows-shaped path that has no quote-free spelling is
// unspawnable: agy's `cmd /C` spawn is what turns a quote into \" (#353), and
// nothing suggests a POSIX host does that.
func AntigravityHookSpawnable(binary string) bool {
	if !windowsShapedPath(binary) {
		return true
	}
	_, ok := antigravityBareWord(binary)
	return ok
}

// shortPathResolver maps a Windows path to its 8.3 short name. A variable so a
// test can stand in for a volume with, or without, short names.
var shortPathResolver = resolveShortPath

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
