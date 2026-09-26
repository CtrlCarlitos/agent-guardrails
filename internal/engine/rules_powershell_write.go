package engine

import (
	"path"
	"regexp"
	"strings"
)

// The write-target reader for the Windows copy, move and content-writing
// commands (#146). writeTargets only knew the POSIX spellings, so
// `Copy-Item x guardrail.exe` was invisible to the P5.self-config rule that
// already denied `cp x guardrail`. The result feeds only the self-config
// check: extending the out-of-repo-write ask to PowerShell is a separate
// decision.

var psCopyParams = psParams{
	switches: []string{"force", "recurse", "passthru", "whatif", "confirm", "container", "usetransaction"},
	values:   []string{"path", "literalpath", "destination", "filter", "include", "exclude", "credential", "fromsession", "tosession", "stream"},
	paths:    []string{"path", "literalpath"},
}

var psContentParams = psParams{
	switches: []string{"force", "passthru", "whatif", "confirm", "append", "noclobber", "nonewline", "usetransaction", "asbytestream"},
	values:   []string{"path", "literalpath", "filepath", "value", "encoding", "filter", "include", "exclude", "credential", "stream", "width", "itemtype", "name"},
	paths:    []string{"path", "literalpath", "filepath"},
}

var psRenameParams = psParams{
	switches: []string{"force", "passthru", "whatif", "confirm", "usetransaction"},
	values:   []string{"path", "literalpath", "newname", "credential"},
	paths:    []string{"path", "literalpath"},
}

// psCopyMove maps a command name to whether it removes its source.
var psCopyMove = map[string]bool{
	"copy-item": false, "copy": false, "cpi": false, "xcopy": false,
	"move-item": true, "move": true, "mi": true,
}

var psContentWriters = map[string]bool{
	"set-content": true, "add-content": true, "out-file": true,
	"tee-object": true, "new-item": true, "clear-content": true, "ni": true,
}

var psRenamers = map[string]bool{"rename-item": true, "rni": true, "ren": true, "rename": true}

// cmd.exe style switches (/Y, /E, /D:date, /XD) are not operands.
var slashSwitch = regexp.MustCompile(`^/[A-Za-z?][A-Za-z0-9_-]*(:.*)?$`)

func stripSlashSwitches(argv []string) []string {
	out := []string{argv[0]}
	for _, a := range argv[1:] {
		if !slashSwitch.MatchString(a) {
			out = append(out, a)
		}
	}
	return out
}

func winBase(p string) string {
	return path.Base(strings.ReplaceAll(p, `\`, "/"))
}

func winJoin(dir, name string) string {
	return strings.TrimRight(strings.ReplaceAll(dir, `\`, "/"), "/") + "/" + name
}

func hasWildcard(p string) bool { return strings.ContainsAny(p, "*?") }

// powershellWriteTargets returns the paths a Windows copy, move, rename or
// content-writing command would create or replace, or ok=false for any other
// command. A destination that may be a directory also yields the file inside
// it named after each source, and, when the source is a wildcard or a whole
// directory, the installed binary's own name.
func powershellWriteTargets(argv []string) (targets []string, ok bool) {
	if len(argv) == 0 {
		return nil, false
	}
	command := head(argv)
	if command == "robocopy" {
		operands := stripSlashSwitches(argv)[1:]
		if len(operands) < 2 {
			return nil, true
		}
		destination, files := operands[1], operands[2:]
		targets = append(targets, destination)
		wild := len(files) == 0
		for _, f := range files {
			targets = append(targets, winJoin(destination, f))
			wild = wild || hasWildcard(f)
		}
		if wild {
			targets = append(targets, winJoin(destination, "guardrail.exe"), winJoin(destination, "guardrail"))
		}
		return targets, true
	}
	if removes, isCopy := psCopyMove[command]; isCopy {
		binding := bindPS(stripSlashSwitches(argv), psCopyParams)
		operands := binding.operands
		var sources []string
		destination := binding.values["destination"]
		if destination != "" {
			sources = operands
		} else if len(operands) >= 2 {
			destination, sources = operands[len(operands)-1], operands[:len(operands)-1]
		} else {
			return nil, true
		}
		targets = append(targets, destination)
		for _, source := range sources {
			if hasWildcard(source) {
				targets = append(targets, winJoin(destination, "guardrail.exe"), winJoin(destination, "guardrail"))
			} else {
				targets = append(targets, winJoin(destination, winBase(source)))
			}
			if removes {
				targets = append(targets, source)
			}
		}
		return targets, true
	}
	if psRenamers[command] {
		binding := bindPS(argv, psRenameParams)
		operands := binding.operands
		newName := binding.values["newname"]
		if newName == "" && len(operands) >= 2 {
			newName, operands = operands[len(operands)-1], operands[:len(operands)-1]
		}
		if len(operands) == 0 {
			return nil, true
		}
		targets = append(targets, operands[0])
		if newName != "" {
			dir := path.Dir(strings.ReplaceAll(operands[0], `\`, "/"))
			targets = append(targets, winJoin(dir, newName))
		}
		return targets, true
	}
	if psContentWriters[command] {
		binding := bindPS(argv, psContentParams)
		if len(binding.operands) == 0 {
			return nil, true
		}
		targets = append(targets, binding.operands[0])
		if name := binding.values["name"]; name != "" {
			targets = append(targets, winJoin(binding.operands[0], name))
		}
		return targets, true
	}
	return nil, false
}

// powershellWriteCandidates lifts powershellWriteTargets over every simple
// command of a parsed shell line.
func powershellWriteCandidates(tc ToolCall, bash *bashAnalysis) []pathCandidate {
	if bash == nil || bash.err != nil {
		return nil
	}
	var out []pathCandidate
	for _, s := range bash.orderedSimples {
		targets, ok := powershellWriteTargets(s.Argv)
		if !ok {
			continue
		}
		for _, target := range targets {
			out = append(out, pathCandidate{posix: true, path: target, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot})
		}
	}
	return out
}
