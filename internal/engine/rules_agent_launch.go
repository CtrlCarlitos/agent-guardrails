package engine

import (
	"encoding/json"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// A session can start another agent host from its shell. Started the ordinary
// way, the child loads the same user settings and so runs the same Guardrail
// hook: nothing is lost. A command can also start the child without those
// settings, and then nothing supervises it. That is the agent configuring away
// the thing supervising it (CR-14), one process removed, and ADR-0013 already
// says an out-of-process delegation needs a denial path.
//
// The rule reads the command line: the host's own flags, and the environment
// the command gives it. A launch from a script file or an interpreter's code is
// outside it (ADR-0012).

// UnsupervisedChildRule has its own ID so an operator who waives
// P5.self-config for instruction files does not waive this with it.
const UnsupervisedChildRule = "P5.unsupervised-child"

var agentHosts = map[string]bool{"claude": true, "codex": true, "opencode": true, "agy": true}

// agentHostPackages are the package names a wrapper such as npx resolves to a
// host binary.
var agentHostPackages = map[string]string{
	"@anthropic-ai/claude-code": "claude",
	"@openai/codex":             "codex",
	"opencode-ai":               "opencode",
}

// agentLaunchExempt are commands that never run their arguments. A host's name
// among their operands is a mention: `echo claude --bare`, `cd codex`.
var agentLaunchExempt = map[string]bool{
	"echo": true, "printf": true, "grep": true, "egrep": true, "fgrep": true, "rg": true,
	"git": true, "gh": true, "which": true, "where": true, "whereis": true, "type": true,
	"man": true, "ls": true, "cat": true, "head": true, "tail": true, "less": true,
	"cd": true, "pushd": true, "mkdir": true, "rmdir": true, "rm": true, "cp": true,
	"mv": true, "touch": true, "find": true, "test": true, "[": true,
}

// agentHostVariable reports a variable a host, or the hook it runs, uses to
// find its settings: the home and configuration roots, and PATH, through which
// Claude Code and Antigravity resolve the hook's bare `guardrail` command.
func agentHostVariable(name string) bool {
	name = strings.ToUpper(strings.TrimSuffix(name, "+"))
	switch name {
	case "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
		"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "PATH",
		"CLAUDE_CONFIG_DIR", "CLAUDE_CODE_SIMPLE", "CODEX_HOME", "ANTIGRAVITY_APP_DATA_DIR":
		return true
	}
	return strings.HasPrefix(name, "OPENCODE_CONFIG") || strings.HasPrefix(name, "GUARDRAIL_")
}

// agentHostName names the host a word starts: the binary, a Windows shim of it
// (`claude.cmd`), a package name with or without a version, or Claude Code's
// entry script.
func agentHostName(word string) string {
	lower := strings.ToLower(strings.ReplaceAll(word, `\`, "/"))
	if strings.HasSuffix(lower, "@anthropic-ai/claude-code/cli.js") {
		return "claude"
	}
	unversioned := lower
	if at := strings.LastIndex(unversioned, "@"); at > 0 {
		unversioned = unversioned[:at]
	}
	if host, ok := agentHostPackages[unversioned]; ok {
		return host
	}
	base := unversioned[strings.LastIndex(unversioned, "/")+1:]
	base = strings.TrimRight(base, ". ")
	for _, extension := range []string{".exe", ".cmd", ".bat", ".ps1", ".com"} {
		base = strings.TrimSuffix(base, extension)
	}
	if agentHosts[base] {
		return base
	}
	return ""
}

// codexHarmlessOverrides are `-c` keys that choose a model and reach nothing
// else. Any other key is denied: the Engine does not know Codex's whole
// configuration, and `features.*` and a profile can turn hooks off.
var codexHarmlessOverrides = map[string]bool{
	"model": true, "model_reasoning_effort": true, "model_reasoning_summary": true,
	"model_verbosity": true, "service_tier": true,
}

// flagValue returns the argument of `--flag value`, `--flag=value` or, for a
// short flag, `-fvalue`.
func flagValue(args []string, index int, long, short string) (string, bool) {
	arg := args[index]
	if value, ok := strings.CutPrefix(arg, long+"="); ok && long != "" {
		return value, true
	}
	if arg == long || short != "" && arg == short {
		if index+1 < len(args) {
			return args[index+1], true
		}
		return "", true
	}
	if short != "" && strings.HasPrefix(arg, short) && !strings.HasPrefix(arg, "--") {
		return strings.TrimPrefix(strings.TrimPrefix(arg, short), "="), true
	}
	return "", false
}

// agentHostUnsupervised reports why a host's arguments would start it without
// the hook, or "". Arguments after `--` are operands, not flags.
func agentHostUnsupervised(host string, args []string) string {
	for index, arg := range args {
		if arg == "--" {
			break
		}
		switch host {
		case "claude":
			switch arg {
			case "--bare":
				return "--bare skips hooks"
			case "--restricted":
				return "--restricted ignores the user settings that hold the hook"
			}
			if value, ok := flagValue(args, index, "--setting-sources", ""); ok {
				user := false
				for _, source := range strings.Split(value, ",") {
					user = user || strings.TrimSpace(source) == "user"
				}
				if !user {
					return "--setting-sources without `user` leaves out the settings that hold the hook"
				}
			}
			if value, ok := flagValue(args, index, "--settings", ""); ok {
				var settings map[string]json.RawMessage
				if json.Unmarshal([]byte(value), &settings) != nil {
					return "--settings names a file or a value the Engine cannot read; it outranks the user settings"
				}
				for _, key := range []string{"disableAllHooks", "env"} {
					if _, present := settings[key]; present {
						return "--settings sets " + key + ", which outranks the user settings"
					}
				}
			}
		case "codex":
			switch arg {
			case "--ignore-user-config":
				return "--ignore-user-config does not load the user configuration"
			}
			if _, ok := flagValue(args, index, "--disable", ""); ok {
				return "--disable turns a Codex feature off"
			}
			if _, ok := flagValue(args, index, "--profile", "-p"); ok {
				return "--profile layers another configuration over the user's"
			}
			if value, ok := flagValue(args, index, "--config", "-c"); ok {
				key, _, _ := strings.Cut(value, "=")
				if !codexHarmlessOverrides[strings.TrimSpace(key)] {
					return "-c " + key + " overrides the user configuration"
				}
			}
		case "agy":
			if _, ok := flagValue(args, index, "--settings", ""); ok {
				return "--settings replaces settings for the session"
			}
		}
	}
	return ""
}

// noteLaunch records a host this command starts, and why its arguments
// would start it unsupervised, if they would.
func (scan *launchScan) noteLaunch(host string, args []string) {
	scan.launched = host
	if scan.denial == "" {
		scan.denial = agentHostUnsupervised(host, args)
	}
}

var (
	braceExpansion  = regexp.MustCompile(`\{[^{}]*(,|\.\.)[^{}]*\}`)
	psEnvAssignment = regexp.MustCompile(`(?i)^\$\{?env:([A-Za-z_][A-Za-z0-9_]*)`)
	psEnvDrive      = regexp.MustCompile(`(?i)^env:\\?([A-Za-z_][A-Za-z0-9_]*)$`)
	shellAssignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\+?=`)
)

type launchWord struct {
	value   string // static value, or the source text when not static
	static  bool
	literal bool // every part unquoted: subject to brace expansion
}

// launchScan walks a command, and the commands it hands to a nested shell, for
// host launches and for the environment it sets for them.
type launchScan struct {
	launched        string   // a host this command starts
	denial          string   // why a launch is unsupervised
	ambient         []string // host variables set for the rest of the command
	ambientAtLaunch int      // ambient entries seen before the last launch
}

func (scan *launchScan) source(src string, depth int) {
	if scan.denial != "" || depth > 3 {
		return
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if scan.denial != "" {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			scan.call(node, src, depth)
		case *syntax.DeclClause:
			scan.declaration(node, src)
		}
		return scan.denial == ""
	})
}

// declaration reads `export NAME=value` and its relatives, which the parser
// keeps apart from ordinary commands.
func (scan *launchScan) declaration(decl *syntax.DeclClause, src string) {
	for _, assign := range decl.Args {
		if assign.Name != nil {
			if agentHostVariable(assign.Name.Value) {
				scan.ambient = append(scan.ambient, strings.ToUpper(assign.Name.Value))
			}
			continue
		}
		if assign.Value == nil {
			continue
		}
		// A name the parser could not read as one: quoted, or built from a
		// variable (`export "HO""ME"=/x`, `export $H=/x`).
		value, static := staticWord(assign.Value, false)
		if !static {
			value = src[assign.Value.Pos().Offset():assign.Value.End().Offset()]
		}
		name, _, assigned := strings.Cut(value, "=")
		switch {
		case assigned && (!static || strings.ContainsAny(name, "$`")):
			scan.ambient = append(scan.ambient, "a variable whose name is not written out")
		case assigned && agentHostVariable(name):
			scan.ambient = append(scan.ambient, strings.ToUpper(strings.TrimSuffix(name, "+")))
		}
	}
}

func (scan *launchScan) call(call *syntax.CallExpr, src string, depth int) {
	var inline []string
	for _, assign := range call.Assigns {
		if assign.Name != nil && agentHostVariable(assign.Name.Value) {
			inline = append(inline, strings.ToUpper(assign.Name.Value))
		}
	}
	words := make([]launchWord, 0, len(call.Args))
	for _, arg := range call.Args {
		word := launchWord{literal: true}
		for _, part := range arg.Parts {
			if _, ok := part.(*syntax.Lit); !ok {
				word.literal = false
			}
		}
		word.value, word.static = staticWord(arg, false)
		if !word.static {
			word.value = src[arg.Pos().Offset():arg.End().Offset()]
		}
		words = append(words, word)
	}
	if len(words) == 0 {
		// `HOME=/x` alone: set for everything after it in this shell.
		scan.ambient = append(scan.ambient, inline...)
		return
	}
	command := head([]string{words[0].value})
	scan.setsEnvironment(command, words)
	scan.nestedShell(command, words, depth)

	if agentLaunchExempt[command] {
		return
	}
	at := -1
	for index, word := range words {
		if agentHostName(word.value) != "" {
			at = index
			break
		}
	}
	if at < 0 {
		return
	}
	host := agentHostName(words[at].value)
	scan.launched = host
	scan.ambientAtLaunch = len(scan.ambient)
	var args []string
	for _, word := range words[at+1:] {
		if word.value == "--" {
			break
		}
		if word.literal && braceExpansion.MatchString(word.value) {
			scan.denial = "an argument is built by brace expansion, so the flags the host receives are not the ones shown"
			return
		}
	}
	for _, word := range words[at+1:] {
		// Start-Process takes the host's arguments as one string or a list.
		if command == "start-process" || command == "saps" || command == "start" {
			args = append(args, strings.FieldsFunc(word.value, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })...)
			continue
		}
		args = append(args, word.value)
	}
	scan.noteLaunch(host, args)
	if scan.denial != "" {
		return
	}
	if len(inline) > 0 {
		scan.denial = "the command sets " + inline[0] + ", which the host or its hook uses to find its settings"
		return
	}
	// Words before the host: `env NAME=value`, `env -i`, a wrapper's options.
	env := false
	for _, word := range words[:at] {
		name := head([]string{word.value})
		if name == "env" {
			env = true
			continue
		}
		if match := shellAssignment.FindStringSubmatch(word.value); match != nil && agentHostVariable(match[1]) {
			scan.denial = "the command sets " + strings.ToUpper(match[1]) + ", which the host or its hook uses to find its settings"
			return
		}
		if env && !word.static && strings.Contains(word.value, "=") {
			scan.denial = "env sets a variable whose name is not written out"
			return
		}
		if env && (word.value == "-" || word.value == "--ignore-environment" || strings.HasPrefix(word.value, "--unset") ||
			strings.HasPrefix(word.value, "-") && !strings.HasPrefix(word.value, "--") && strings.ContainsAny(word.value, "iu")) {
			scan.denial = "env clears or unsets the environment the host finds its settings through"
			return
		}
	}
}

// setsEnvironment records a host variable set for the rest of the command:
// export and its relatives, cmd's set, the commands that write a named
// variable, and PowerShell's environment drive.
func (scan *launchScan) setsEnvironment(command string, words []launchWord) {
	note := func(name string) {
		if agentHostVariable(name) {
			scan.ambient = append(scan.ambient, strings.ToUpper(strings.TrimSuffix(name, "+")))
		}
	}
	if match := psEnvAssignment.FindStringSubmatch(words[0].value); match != nil {
		note(match[1])
		return
	}
	switch command {
	case "export", "declare", "typeset", "readonly", "local", "set", "setx":
		for index, word := range words[1:] {
			name, _, assigned := strings.Cut(word.value, "=")
			switch {
			case assigned && strings.ContainsAny(name, "$`"):
				// `export $H=/x`: the name is not written out.
				scan.ambient = append(scan.ambient, "a variable whose name is not written out")
			case assigned:
				note(name)
			case command == "setx" && index == 0:
				note(word.value)
			}
		}
	case "unset", "read", "mapfile", "readarray":
		for _, word := range words[1:] {
			note(word.value)
		}
	case "printf":
		for index, word := range words[1:] {
			if word.value == "-v" && index+2 < len(words) {
				note(words[index+2].value)
			}
		}
	case "set-item", "si", "new-item", "ni", "set-content", "sc", "remove-item", "ri", "clear-item", "cli":
		for _, word := range words[1:] {
			if match := psEnvDrive.FindStringSubmatch(word.value); match != nil {
				note(match[1])
			}
		}
	}
}

// nestedShell reads the command a shell is handed as a string.
func (scan *launchScan) nestedShell(command string, words []launchWord, depth int) {
	var flags map[string]bool
	switch command {
	case "bash", "sh", "zsh", "dash", "ksh":
		flags = map[string]bool{"-c": true, "-lc": true, "-ic": true, "-cl": true}
	case "cmd":
		flags = map[string]bool{"/c": true, "/k": true}
	case "pwsh", "powershell":
		flags = map[string]bool{"-c": true, "-command": true}
	case "eval":
		scan.source(joinWords(words[1:]), depth+1)
		return
	default:
		return
	}
	for index, word := range words[1:] {
		if flags[strings.ToLower(word.value)] {
			scan.source(joinWords(words[index+2:]), depth+1)
			return
		}
	}
}

func joinWords(words []launchWord) string {
	values := make([]string, 0, len(words))
	for _, word := range words {
		values = append(values, word.value)
	}
	return strings.Join(values, " ")
}

func checkUnsupervisedAgentLaunch(tc ToolCall, bash *bashAnalysis) *policy.Verdict {
	if bash == nil || bash.err != nil {
		return nil
	}
	scan := &launchScan{}
	scan.source(tc.Command, 0)
	// The tokenizer's own reading catches what the text does not show: a
	// variable holding the host's name or a flag, a wrapper it unwraps.
	if scan.launched == "" {
		// No launch the text scan saw: a launch the tokenizer finds has no
		// order relationship to what the text scan collected, so every
		// ambient variable counts for it.
		scan.ambientAtLaunch = len(scan.ambient)
	}
	for _, s := range bash.orderedSimples {
		if len(s.Argv) == 0 || scan.denial != "" {
			continue
		}
		for index, word := range s.Argv {
			host := agentHostName(word)
			if host == "" || index > 0 && agentLaunchExempt[head(s.Argv)] {
				continue
			}
			scan.noteLaunch(host, s.Argv[index+1:])
			break
		}
	}
	if scan.denial == "" && scan.launched != "" && scan.ambientAtLaunch > 0 {
		scan.denial = "the command sets " + scan.ambient[0] + ", which the host or its hook uses to find its settings"
	}
	if scan.denial == "" {
		return nil
	}
	return &policy.Verdict{Decision: policy.Deny, RuleID: UnsupervisedChildRule,
		Reason: "starts a child agent session (" + scan.launched + ") that guardrail would not supervise: " + scan.denial +
			". Start it without that, so it loads the same user settings and hooks as this session"}
}
