package engine

import (
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// cmd.exe is the third shell a Windows plane can submit, after POSIX and
// PowerShell. Its switches are forward-slashed, so `/s` and `/q` reach the
// tokenizer as ordinary operands and every family keyed on a recursive-delete
// flag saw an unrecognised command with three paths (#139).
//
// Same approach as the PowerShell projection: a cmd builtin is rewritten into
// the POSIX command it stands for and handed to the rule that already owns it,
// so there is one containment decision for `rm -rf`, `Remove-Item -Recurse`
// and `del /s`, one waiver, and one place the path logic lives.
//
// The semantics were measured on disposable trees rather than assumed:
//
//	del /s /q <dir>   every file beneath <dir>, recursively; <dir> remains
//	del /q  <dir>     files directly in <dir> only
//	rd  /s /q <dir>   the whole tree, <dir> included
//	rd      <dir>     fails on a non-empty directory (exit 145)
//	erase             an alias of del
//	DEL /S /Q         switches are case-insensitive
//	del -s -q         rejected by cmd; dash switches are not cmd syntax

// cmdSwitch reports whether arg is one of the named cmd switches, returning
// its lowercased name. A `/x:value` switch such as `/FS:NTFS` matches on `fs`.
//
// The switch names are enumerated rather than accepting any `/token`, because
// a rule cannot know which shell submitted the string and on POSIX a leading
// slash is an absolute path. Reading `/etc` as an unknown switch would consume
// the operand and leave the delete with nothing to judge — a fail-open on the
// host where `/etc` is real. Anything outside the set stays an operand, so an
// unrecognised switch is judged as a path and fails closed instead.
func cmdSwitch(arg string, known map[string]bool) (string, bool) {
	if len(arg) < 2 || arg[0] != '/' {
		return "", false
	}
	body := strings.ToLower(arg[1:])
	if name, _, found := strings.Cut(body, ":"); found {
		body = name
	}
	if !known[body] {
		return "", false
	}
	return body, true
}

// cmdDeleteAliases are the builtins that remove files or directories. `rm` is
// absent: it is not a cmd builtin, and the POSIX family already owns the name.
var cmdDeleteAliases = map[string]bool{
	"del": true, "erase": true, "rd": true, "rmdir": true,
}

// cmdDeleteSwitches are every switch `del`, `erase`, `rd` and `rmdir` accept.
var cmdDeleteSwitches = map[string]bool{
	"s": true, "q": true, "f": true, "a": true, "p": true,
}

// checkCmdDelete projects a cmd recursive delete onto the rm rule.
//
// `/s` is the only recursion marker cmd has, and it is what separates a
// destructive call from `rd <dir>`, which fails on a non-empty directory and
// is left to the existing P1.rmdir ask. `/q` and `/f` both suppress a
// protection — the confirmation prompt and the read-only attribute — and map
// to force, matching how the PowerShell projection reads `-Force`.
func checkCmdDelete(s Simple, tc ToolCall, pol *policy.Policy) *policy.Verdict {
	if !cmdDeleteAliases[head(s.Argv)] {
		return nil
	}
	recursive, force := false, false
	var operands []string
	for _, arg := range s.Argv[1:] {
		name, isSwitch := cmdSwitch(arg, cmdDeleteSwitches)
		if !isSwitch {
			operands = append(operands, arg)
			continue
		}
		switch name {
		case "s":
			recursive = true
		case "q", "f":
			force = true
		}
	}
	if !recursive && !force {
		// Not a cmd-shaped destructive call. `rmdir <dir>` and a bare `rd`
		// keep the ask the POSIX family already gives them.
		return nil
	}
	if len(operands) == 0 {
		// Every word was a switch, so there is no target to judge. Returning
		// nil hands the call back to the families that key on the name, which
		// is where `rd /s` keeps its P1.rmdir ask.
		return nil
	}
	flags := "-"
	if recursive {
		flags += "r"
	}
	if force {
		flags += "f"
	}
	argv := append([]string{"rm", flags}, operands...)
	return checkRmRf(commandDerivedFromAt(s, argv, -1), tc, pol)
}

// cmdDiskDestroyers wipe a volume or a partition table. `diskpart` is a
// Windows-only name and needs no qualification; `format` is a plausible name
// for an ordinary tool on any host, so it counts only when the call carries
// cmd's own shape — a drive-letter operand or one of format's switches.
var cmdDiskDestroyers = map[string]bool{"diskpart": true}

// cmdFormatSwitches are the switches cmd's volume formatter accepts.
var cmdFormatSwitches = map[string]bool{
	"fs": true, "v": true, "q": true, "c": true, "x": true, "a": true,
	"p": true, "y": true, "r": true, "d": true, "t": true, "n": true,
	"i": true, "l": true,
}

func checkCmdDiskDestroyer(s Simple) *policy.Verdict {
	command := head(s.Argv)
	if cmdDiskDestroyers[command] {
		return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
			Reason: "filesystem-destroying command: " + command}
	}
	if command != "format" || !cmdShapedFormat(s.Argv) {
		return nil
	}
	return &policy.Verdict{Decision: policy.Deny, RuleID: "P1.mkfs",
		Reason: "filesystem-destroying command: " + command}
}

// cmdShapedFormat reports whether a `format` call is cmd's volume formatter
// rather than some other tool of the same name: a drive-letter operand such
// as `C:`, or one of format's own switches.
func cmdShapedFormat(argv []string) bool {
	for _, arg := range argv[1:] {
		if _, isSwitch := cmdSwitch(arg, cmdFormatSwitches); isSwitch {
			return true
		}
		if len(arg) == 2 && arg[1] == ':' && isASCIILetterByte(arg[0]) {
			return true
		}
	}
	return false
}
