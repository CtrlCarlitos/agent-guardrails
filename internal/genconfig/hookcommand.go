package genconfig

import (
	"runtime"
	"strings"
)

// HookCommand renders the binary path and its arguments as one command
// string for a plane's floor.
//
// The string is handed to whatever shell the plane's runtime spawns hooks
// with, and the two shells disagree about almost everything. A bare Windows
// path survives cmd.exe and dies in a POSIX shell, where every backslash is
// an escape character:
//
//	C:\Users\u\.local\bin\guardrail.exe hook claude
//	bash: C:Usersubinguardrail.exe: command not found
//
// A PreToolUse hook that cannot spawn is a silent no-op, so that spelling
// registered fine, reported green in doctor, and enforced nothing for four
// days on a Windows host (#149). Quoting is therefore not cosmetic here: it
// is the difference between a guard and the appearance of one.
//
// Windows paths take double quotes with forward slashes, the intersection
// cmd.exe and POSIX shells both accept — the spelling of graft's working
// hook in the same settings file. A POSIX path that needs protecting takes
// single quotes, because double quotes there still expand `$` and backticks;
// that is what codex already emitted.
//
// A word with nothing for a shell to act on is left alone. `guardrail` and
// `/usr/local/bin/guardrail` are already exactly what the shell should see,
// and quoting them would rewrite the floor of every POSIX install for no
// safety gain — drift, a re-merge, and an approval prompt, to change nothing.
// It would also erase a deliberate distinction: only opencode pins an
// absolute PATH-resolved binary, because its plugin spawns the executable
// directly; claude and antigravity keep the bare name so the shell resolves
// it on PATH at hook time.
func HookCommand(binary string, args ...string) string {
	word := binary
	switch {
	case windowsShapedPath(binary):
		word = `"` + strings.ReplaceAll(binary, `\`, "/") + `"`
	case !shellSafeWord(binary):
		word = quotePosixWord(binary)
	}
	if len(args) == 0 {
		return word
	}
	return word + " " + strings.Join(args, " ")
}

// shellSafeWord reports whether a word passes through a shell untouched: it
// is non-empty, cannot be mistaken for an option, and holds only characters
// no shell assigns meaning to. The set is deliberately small — anything not
// on it gets quoted, so a new metacharacter is safe by default rather than
// dangerous by omission.
func shellSafeWord(word string) bool {
	if word == "" || strings.HasPrefix(word, "-") {
		return false
	}
	for i := 0; i < len(word); i++ {
		c := word[i]
		if isASCIILetter(c) || c >= '0' && c <= '9' {
			continue
		}
		if strings.IndexByte("._/+-", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// windowsShapedPath reports whether a path is meant for a Windows filesystem:
// a drive letter, or a UNC share. Detection is on the path and not on
// runtime.GOOS, because gen-config emits a floor for wherever the binary will
// live, which need not be this machine.
//
// A bare backslash elsewhere only counts when this host is Windows. A POSIX
// filename may legally contain one, and rewriting it would break a path that
// works today; on Windows nothing else that shape can be.
func windowsShapedPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		return true
	}
	if strings.HasPrefix(p, `\\`) {
		return true
	}
	return runtime.GOOS == "windows" && strings.Contains(p, `\`)
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// quotePosixWord wraps a word in single quotes so a shell reads it whole,
// closing and reopening around any apostrophe it contains.
func quotePosixWord(word string) string {
	return "'" + strings.ReplaceAll(word, "'", `'"'"'`) + "'"
}

// UnquotedShellHazard reports why a hook command cannot be trusted to spawn,
// or "" when it is safe. doctor uses it: a floor that registers a command no
// shell can run is worse than a missing one, because every other check goes
// green.
func UnquotedShellHazard(command string) string {
	executable := leadingWord(command)
	switch {
	case executable == "":
		return ""
	case strings.HasPrefix(executable, `"`), strings.HasPrefix(executable, `'`):
		return ""
	case strings.Contains(executable, `\`):
		return "the binary path is unquoted and contains a backslash, which a POSIX shell reads as an escape character; the hook silently fails to spawn"
	case strings.Contains(command, " ") && unquotedPathWithSpace(command):
		return "the binary path is unquoted and contains a space, so the shell splits it into a command and an argument"
	}
	return ""
}

// leadingWord is the command's executable as the shell would take it: text up
// to the first space, unless the command opens with a quote, in which case the
// quoted span is the word.
func leadingWord(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	if quote := command[0]; quote == '"' || quote == '\'' {
		if end := strings.IndexByte(command[1:], quote); end >= 0 {
			return command[:end+2]
		}
		return command
	}
	if space := strings.IndexByte(command, ' '); space >= 0 {
		return command[:space]
	}
	return command
}

// unquotedPathWithSpace reports whether an unquoted executable was cut short
// by a space belonging to the path rather than by the boundary before a real
// argument.
//
// "is `a b` one path or a command and an argument" has no answer in general
// without touching the filesystem. It has an answer here, because this
// function only ever sees guardrail's own floor commands, and those have a
// known shape: `<binary> hook <plane> …`. If `hook` is present but is not the
// word immediately after the executable, the executable was split.
//
// Two boundaries, both deliberate:
//
//   - A command with no `hook` word is not a shape this can reason about. It
//     falls back to the older separator signal, which catches the obvious
//     `…/my dir/g …` and stays quiet otherwise rather than inventing a hazard.
//   - A path whose final component is literally `hook` defeats the structural
//     check, since the word after the executable is then `hook` by accident.
//     Contrived, and left as known residue rather than chased with a weaker
//     heuristic that would cost false positives.
func unquotedPathWithSpace(command string) bool {
	fields := strings.Fields(command)
	for i, f := range fields {
		if f != "hook" {
			continue
		}
		// `hook` at index 1 means the executable is exactly one word, as
		// emitted. Anything later means the words before it are fragments of a
		// path the shell split.
		return i > 1
	}
	return looksLikePathWithSpace(command)
}

// looksLikePathWithSpace is the fallback signal for a command with no `hook`
// word: a separator after the first space and before the next one.
func looksLikePathWithSpace(command string) bool {
	space := strings.IndexByte(command, ' ')
	if space < 0 {
		return false
	}
	rest := command[space+1:]
	if next := strings.IndexByte(rest, ' '); next >= 0 {
		rest = rest[:next]
	}
	return strings.ContainsAny(rest, `/\`)
}
