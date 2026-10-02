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

var psRemoveParams = psParams{
	switches: []string{"force", "recurse", "whatif", "confirm", "usetransaction"},
	values:   []string{"path", "literalpath", "filter", "include", "exclude", "credential", "stream"},
	paths:    []string{"path", "literalpath"},
}

// psCopyMove maps a command name to whether it removes its source.
var psCopyMove = map[string]bool{
	"copy-item": false, "copy": false, "cpi": false, "xcopy": false,
	"move-item": true, "move": true, "mi": true,
}

// psRemovers are the Windows delete commands: the cmdlet, its `ri` alias, and
// cmd's `del`/`erase` (also PowerShell aliases). `rm`, `rmdir` and `rd` reach
// the self-config rule through the POSIX reader already. Deleting the
// installed binary disables enforcement as surely as replacing it (#146).
var psRemovers = map[string]bool{"remove-item": true, "ri": true, "del": true, "erase": true}

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
	if psRemovers[command] {
		binding := bindPS(stripSlashSwitches(argv), psRemoveParams)
		return binding.operands, true
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
			for _, spelling := range windowsTargetSpellings(target) {
				out = append(out, pathCandidate{posix: true, path: spelling, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot})
			}
		}
	}
	return out
}

// windowsTargetSpellings returns the target plus the spellings Win32 resolves
// it to: forward slashes (so `~\.local\bin\x` is read like `~/.local/bin/x`)
// and, for a Win32 path, the name with trailing dots and spaces stripped
// (`guardrail.exe.` is guardrail.exe, #178).
func windowsTargetSpellings(target string) []string {
	out := []string{target}
	slashed := strings.ReplaceAll(target, `\`, "/")
	if slashed != target {
		out = append(out, slashed)
	}
	if win32ResolvedPath(target) {
		if trimmed := strings.TrimRight(slashed, ". "); trimmed != slashed && trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// installedBinaryNames are the file names the enforcement binary is installed
// under.
var installedBinaryNames = []string{"guardrail.exe", "guardrail"}

// installedBinaryGlobs are the self-config globs that name the binary itself.
var installedBinaryGlobs = []string{
	"**/.local/bin/guardrail", "**/bin/guardrail",
	"**/.local/bin/guardrail.exe", "**/bin/guardrail.exe",
}

// movedAwayBinary returns the installed binary's path when a POSIX `mv` (or
// PowerShell's `mv` alias of Move-Item) takes it as a source: moving it away
// disables enforcement as surely as replacing it (#146). Only the binary
// counts here; moving other self-config files is judged by where they land.
func movedAwayBinary(tc ToolCall, bash *bashAnalysis) string {
	if bash == nil || bash.err != nil {
		return ""
	}
	for _, s := range bash.orderedSimples {
		if head(s.Argv) != "mv" {
			continue
		}
		for _, source := range moveSourceTargets(s.Argv) {
			spellings := windowsTargetSpellings(source)
			spellings = append(spellings, binaryWildcardExpansions(source)...)
			for _, spelling := range spellings {
				candidate := pathCandidate{posix: true, path: spelling, cwd: s.Cwd, cwdUnknown: s.cwdUnknown, repoRoot: tc.RepoRoot}
				if matchesScoped(candidate, installedBinaryGlobs, nil) {
					return spelling
				}
			}
		}
	}
	return ""
}

// deletedInstallDirectory returns the install directory (`.local/bin`, the
// location binaryWildcardExpansions recognises) when a directory delete takes
// it as a target: POSIX `rmdir` or `rm` (any flags), or PowerShell's
// Remove-Item and its aliases (#404). On a non-empty directory these fail,
// but the binary's own directory is never a session's to delete.
func deletedInstallDirectory(tc ToolCall, bash *bashAnalysis) string {
	if bash == nil || bash.err != nil {
		return ""
	}
	for _, s := range bash.orderedSimples {
		var targets []string
		switch command := head(s.Argv); {
		case command == "rm" || command == "rmdir" && !psCmdletShaped(s.Argv, removeItemParams):
			targets = posixOperands(s.Argv)
		case removeItemAliases[command]:
			targets = bindPS(s.Argv, removeItemParams).operands
		default:
			continue
		}
		for _, target := range targets {
			if isInstallDirectory(target, s.Cwd) {
				return target
			}
		}
	}
	return ""
}

func posixOperands(argv []string) []string {
	var out []string
	options := true
	for _, arg := range argv[1:] {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		out = append(out, arg)
	}
	return out
}

func isInstallDirectory(target, cwd string) bool {
	slashed := strings.ReplaceAll(strings.Trim(target, `'"`), `\`, "/")
	if !strings.HasPrefix(slashed, "~") && !path.IsAbs(slashed) && !isWindowsDrivePath(slashed) && cwd != "" {
		slashed = strings.ReplaceAll(cwd, `\`, "/") + "/" + slashed
	}
	cleaned := strings.ToLower(path.Clean(slashed))
	return cleaned == "~/.local/bin" || strings.HasSuffix(cleaned, "/.local/bin")
}

// binaryWildcardExpansions returns the installed binary's path when a
// wildcard target would match it: `Remove-Item ~\.local\bin\*.exe` and
// `rm ~/.local/bin/guardrail*` delete it without naming it. The expansion is
// kept to a pattern that names guardrail or a directory that is the install
// location (`.local/bin`), so `rm bin/*` in a repository's build output is not
// read as deleting the installed binary.
func binaryWildcardExpansions(target string) []string {
	slashed := strings.ReplaceAll(target, `\`, "/")
	base := strings.ToLower(path.Base(slashed))
	if !hasWildcard(base) {
		return nil
	}
	dir := path.Dir(slashed)
	installDir := strings.HasSuffix(strings.ToLower("/"+dir), "/.local/bin")
	if !installDir && !strings.Contains(base, "guard") {
		return nil
	}
	var out []string
	for _, name := range installedBinaryNames {
		if matched, err := path.Match(base, name); err == nil && matched {
			out = append(out, winJoin(dir, name))
		}
	}
	return out
}

// mentionsInstalledBinary reports whether opaque text names the installed
// binary by a literal path: a word or quoted string ending in
// `/bin/guardrail` or `/bin/guardrail.exe` in either slash direction. A
// relative `bin/guardrail` (a repository's own build output) does not count,
// and neither does a staged name like `guardrail.exe.old`.
func mentionsInstalledBinary(text string) bool {
	return mentionsInstalledBinaryAt(text, 0)
}

// mentionsInstalledBinaryAt descends into quoted strings: a word that is still
// quoted text when it reaches the rule (`"...('C:\x\guardrail.exe', $b)"`)
// holds the path one quoting level down.
func mentionsInstalledBinaryAt(text string, depth int) bool {
	for _, candidate := range visiblePathCandidates(text) {
		if namesInstalledBinary(candidate) {
			return true
		}
		if depth < 3 && candidate != text && strings.ContainsAny(candidate, `'"`+"`") &&
			mentionsInstalledBinaryAt(candidate, depth+1) {
			return true
		}
	}
	return false
}

func namesInstalledBinary(candidate string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(candidate, `\`, "/"))
	if !strings.Contains(normalized, "/") {
		return false
	}
	normalized = strings.TrimRight(path.Clean(normalized), ". ")
	for _, name := range installedBinaryNames {
		if strings.HasSuffix(normalized, "/bin/"+name) {
			return true
		}
	}
	return false
}
