package engine

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// stdoutFate records where a statement's standard output ends up (#436).
//
// Everything a command prints enters the session and is sent to the model
// provider, so a command whose output is a credential is only safe when that
// output never reaches the session: captured by a command substitution whose
// value is handed to another command, piped into a program that reads a
// credential on stdin, or discarded. The fate is computed from the same parsed
// tree the tokenizer splits into Simples (next to pipelinePositions), so a
// Simple carries it without a second parser.
//
// The zero value is stdoutRoot on purpose: a Simple built by a path that does
// not carry the fate (a function body, an eval replacement, a find callback, a
// watch loop), or a statement the walk does not follow (a `[[ ]]` test, a
// declaration such as `export X=$(...)`), reads as printing into the session,
// so it is never judged contained on its own.
//
// Writes to a file are not recorded here: the rule reads the Simple's own
// Redirects, which already name every file its output can land in.
type stdoutFate uint8

const (
	// stdoutRoot: the output reaches the top of the parsed source. For the
	// tool call itself that is the session; for the body of `bash -c` it is
	// wherever the enclosing shell's output goes, which stripAndUnwrap fills in.
	stdoutRoot stdoutFate = iota
	// stdoutContained: captured by `$(...)` and handed to a command that does
	// not print it, piped into a credential consumer, or sent to /dev/null.
	stdoutContained
	// stdoutExposed: printed (`echo $(...)`), sent to stderr, piped into
	// something that is not a credential consumer, or stored in a shell
	// variable that a later command can print.
	stdoutExposed
)

// stdoutFates walks a parsed source and assigns every statement it can follow
// a fate. Statements it does not follow keep the zero value, stdoutRoot.
func stdoutFates(src string, f *syntax.File) map[*syntax.Stmt]stdoutFate {
	w := fateWalker{src: src, fates: make(map[*syntax.Stmt]stdoutFate)}
	w.list(f.Stmts, stdoutRoot)
	if sourceEnablesXtrace(src, f) {
		// `set -x` prints every expanded command line, token included, to
		// stderr: nothing the substitution captured stays captured.
		for stmt, fate := range w.fates {
			if fate == stdoutContained {
				w.fates[stmt] = stdoutExposed
			}
		}
	}
	return w.fates
}

// inheritStdoutFate gives the statements at the top of a `bash -c`, `cmd /c`
// or `ssh` body the fate of the command that ran them. A shell run with
// xtrace prints what the body's substitutions captured.
func inheritStdoutFate(inner []Simple, outer stdoutFate, xtrace bool) []Simple {
	for index := range inner {
		if inner[index].stdoutFate == stdoutRoot {
			inner[index].stdoutFate = outer
		}
		if xtrace && inner[index].stdoutFate == stdoutContained {
			inner[index].stdoutFate = stdoutExposed
		}
	}
	return inner
}

type fateWalker struct {
	src   string
	fates map[*syntax.Stmt]stdoutFate
}

func (w *fateWalker) list(stmts []*syntax.Stmt, fate stdoutFate) {
	for _, stmt := range stmts {
		w.stmt(stmt, fate)
	}
}

func (w *fateWalker) stmt(stmt *syntax.Stmt, fate stdoutFate) {
	if stmt == nil {
		return
	}
	fate = w.redirectedFate(stmt, fate)
	w.fates[stmt] = fate
	switch command := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		w.call(stmt, command)
	case *syntax.BinaryCmd:
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			// The right side first: a pass-through filter hands its input on
			// to wherever its own output goes.
			w.stmt(command.Y, fate)
			w.stmt(command.X, w.pipeFate(command.Y))
			return
		}
		w.stmt(command.X, fate)
		w.stmt(command.Y, fate)
	case *syntax.Block:
		w.list(command.Stmts, fate)
	case *syntax.Subshell:
		w.list(command.Stmts, fate)
	case *syntax.TimeClause:
		w.stmt(command.Stmt, fate)
	case *syntax.IfClause:
		for clause := command; clause != nil; clause = clause.Else {
			w.list(clause.Cond, fate)
			w.list(clause.Then, fate)
		}
	case *syntax.WhileClause:
		w.list(command.Cond, fate)
		w.list(command.Do, fate)
	case *syntax.ForClause:
		w.list(command.Do, fate)
	case *syntax.CaseClause:
		for _, item := range command.Items {
			w.list(item.Stmts, fate)
		}
	}
}

// redirectedFate applies a statement's own stdout redirects. A discard
// contains the output and stderr exposes it; the last redirect wins, as it
// does in the shell. A file target leaves the fate alone for the Simple's
// Redirects to answer, except in a pipe, where nothing reaches the next stage.
func (w *fateWalker) redirectedFate(stmt *syntax.Stmt, fate stdoutFate) stdoutFate {
	for _, redirect := range stmt.Redirs {
		if redirect.Word == nil {
			continue
		}
		stdout := redirect.N == nil || redirect.N.Value == "1"
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
			if !stdout && redirect.Op != syntax.RdrAll && redirect.Op != syntax.AppAll {
				continue
			}
			target, literal := literalText(w.raw(redirect.Word))
			if literal && discardTarget(target) || isNullDiscard(w.raw(redirect.Word)) {
				fate = stdoutContained
			}
		case syntax.DplOut:
			if !stdout {
				continue
			}
			if target, literal := literalText(w.raw(redirect.Word)); literal && target == "1" {
				continue
			}
			fate = stdoutExposed
		}
	}
	return fate
}

func discardTarget(target string) bool {
	return target == "/dev/null" || strings.EqualFold(target, "nul")
}

// call gives the statements inside the substitutions of one simple command
// their fate, by the role the substituted value plays there.
func (w *fateWalker) call(stmt *syntax.Stmt, call *syntax.CallExpr) {
	consumer, known := w.consumerArgv(call)
	argumentFate, environmentFate, stdinFate := stdoutExposed, stdoutExposed, stdoutExposed
	if known && len(call.Args) > 0 {
		if !consumerPrints(consumer) && !consumerRunsCode(consumer) {
			argumentFate = stdoutContained
		}
		if !consumerPrints(consumer) && !shellEnablesXtrace(consumer) {
			environmentFate = stdoutContained
		}
		if !consumerPrints(consumer) && !interpreterHeads[head(consumer)] {
			stdinFate = stdoutContained
		}
	}
	for index, word := range call.Args {
		if index == 0 {
			// A substituted command name: the shell reports the value back
			// as "command not found".
			w.substitutions(word, stdoutExposed)
			continue
		}
		w.substitutions(word, argumentFate)
	}
	for _, assign := range call.Assigns {
		// With no command this is a plain shell variable, which any later
		// command can print under a name nobody would recognise as secret.
		fate := environmentFate
		if len(call.Args) == 0 {
			fate = stdoutExposed
		}
		if assign.Value != nil {
			w.substitutions(assign.Value, fate)
		}
		if assign.Array != nil {
			for _, element := range assign.Array.Elems {
				w.substitutions(element.Value, stdoutExposed)
			}
		}
	}
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.WordHdoc:
			w.substitutions(redirect.Word, stdinFate)
		case syntax.Hdoc, syntax.DashHdoc:
			w.substitutions(redirect.Hdoc, stdinFate)
		case syntax.RdrIn:
			if redirect.Word != nil && len(redirect.Word.Parts) == 1 {
				if process, ok := redirect.Word.Parts[0].(*syntax.ProcSubst); ok && process.Op == syntax.CmdIn {
					w.list(process.Stmts, stdinFate)
					continue
				}
			}
			w.substitutions(redirect.Word, stdoutExposed)
		default:
			w.substitutions(redirect.Word, stdoutExposed)
		}
	}
}

// substitutions assigns fate to the statements of every command or process
// substitution in a word. Nested substitutions are reached through the
// statements they belong to, so each is judged by its own consumer.
func (w *fateWalker) substitutions(word *syntax.Word, fate stdoutFate) {
	if word == nil {
		return
	}
	syntax.Walk(word, func(node syntax.Node) bool {
		switch substitution := node.(type) {
		case *syntax.CmdSubst:
			w.list(substitution.Stmts, fate)
			return false
		case *syntax.ProcSubst:
			if substitution.Op == syntax.CmdOut {
				// `>(cmd)`: cmd's own output is not captured by anything.
				w.list(substitution.Stmts, stdoutExposed)
			} else {
				w.list(substitution.Stmts, fate)
			}
			return false
		}
		return true
	})
}

// pipeFate is the fate of what a pipeline stage writes into the stage after
// it. A credential consumer contains it; a pass-through filter passes it on
// to wherever the filter's own output goes; anything else exposes it.
func (w *fateWalker) pipeFate(next *syntax.Stmt) stdoutFate {
	first := next
	for {
		binary, ok := first.Cmd.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
			break
		}
		first = binary.X
	}
	call, ok := first.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return stdoutExposed
	}
	for _, redirect := range first.Redirs {
		if redirect.Op == syntax.RdrIn || redirect.Op == syntax.WordHdoc || redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc {
			return stdoutExposed
		}
	}
	consumer, known := w.consumerArgv(call)
	if !known {
		return stdoutExposed
	}
	switch {
	case credentialStdinConsumer(consumer):
		return stdoutContained
	case pipedArgumentConsumer(call, consumer):
		return stdoutContained
	case passThroughFilters[head(consumer)]:
		return w.fates[first]
	}
	return stdoutExposed
}

// pipedArgumentConsumer covers `... | xargs program`: xargs turns its input
// into arguments of a program, which is the argument role. unwrapConsumer has
// already turned an echoing xargs into echo.
func pipedArgumentConsumer(call *syntax.CallExpr, consumer []string) bool {
	if len(call.Args) == 0 {
		return false
	}
	name, ok := literalWord(call.Args[0])
	if !ok || head([]string{name}) != "xargs" {
		return false
	}
	return !consumerPrints(consumer) && !consumerRunsCode(consumer)
}

func xargsEchoes(options []string) bool {
	for _, option := range options {
		if option == "-t" || option == "-p" {
			return true
		}
	}
	return false
}

func (w *fateWalker) raw(word *syntax.Word) string {
	return w.src[word.Pos().Offset():word.End().Offset()]
}

// consumerArgv is the command a call runs once the wrappers that only change
// how it runs are stripped. known is false when the command name is not
// literal or a wrapper could not be read.
func (w *fateWalker) consumerArgv(call *syntax.CallExpr) ([]string, bool) {
	var argv []string
	for index, word := range call.Args {
		raw := w.raw(word)
		if literal, ok := literalText(raw); ok {
			argv = append(argv, literal)
		} else if index == 0 {
			return nil, false
		} else {
			argv = append(argv, raw)
		}
	}
	return unwrapConsumer(argv)
}

func literalWord(word *syntax.Word) (string, bool) {
	return staticWord(word, false)
}

// unwrapConsumer strips the wrappers stripAndUnwrap strips, with the same
// option readers. A bare `env` stays: it prints the environment.
func unwrapConsumer(argv []string) ([]string, bool) {
	for len(argv) > 0 {
		var rest []string
		var err error
		switch head(argv) {
		case "env":
			rest, err = consumeEnv(argv[1:])
			if err == nil && len(rest) == 0 {
				return argv, true
			}
		case "timeout":
			rest, err = consumeTimeout(argv[1:])
		case "nice":
			rest, err = consumeNice(argv[1:])
		case "setsid":
			rest, err = consumeSetsid(argv[1:])
		case "stdbuf":
			rest, err = consumeStdbuf(argv[1:])
		case "nohup":
			rest, err = consumeNoFlags("nohup", argv[1:])
		case "exec":
			rest, err = consumeExec(argv[1:])
		case "builtin":
			rest, err = consumeBuiltin(argv[1:])
		case "command":
			var none bool
			rest, none, err = consumeCommand(argv[1:])
			if none {
				// `command -v X` prints what it looked up.
				return []string{"echo"}, true
			}
		case "time":
			rest = argv[1:]
		case "xargs":
			rest, err = consumeXargs(argv[1:])
			if err == nil && (len(rest) == 0 || xargsEchoes(argv[1:len(argv)-len(rest)])) {
				// Without a program xargs runs echo; -t and -p print the
				// command line they build.
				return []string{"echo"}, true
			}
		default:
			return argv, true
		}
		if err != nil {
			return nil, false
		}
		argv = rest
	}
	return argv, true
}

// printingCommands write their arguments, their input or their environment to
// the session: the consumers a captured credential must never be handed to.
// PowerShell's output cmdlets are here because the PowerShell tool reaches the
// Engine through the same analyser.
var printingCommands = map[string]bool{
	"echo": true, "printf": true, "print": true, "printenv": true, "env": true,
	"cat": true, "tee": true, "type": true, "more": true, "less": true,
	"head": true, "tail": true, "logger": true,
	"write-output": true, "write": true, "write-host": true, "write-error": true,
	"write-warning": true, "write-verbose": true, "write-debug": true,
	"write-information": true, "out-host": true, "out-default": true,
	"out-string": true, "out-file": true, "tee-object": true,
	"set-content": true, "add-content": true,
}

func consumerPrints(argv []string) bool {
	return len(argv) == 0 || printingCommands[head(argv)]
}

// interpreterHeads run code they are given; a credential substituted into
// their code, or fed to them on stdin, becomes code that can print it.
var interpreterHeads = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "mksh": true,
	"ash": true, "fish": true, "csh": true, "tcsh": true, "cmd": true,
	"pwsh": true, "powershell": true, "python": true, "python3": true, "py": true,
	"node": true, "deno": true, "bun": true, "perl": true, "ruby": true, "php": true,
	"eval": true, "source": true, ".": true,
}

// consumerRunsCode reports a consumer whose arguments are code: a shell's -c
// body, an interpreter's -e/-c program, eval. A credential substituted there
// becomes part of a program that can print it.
func consumerRunsCode(argv []string) bool {
	if _, dashC, err := shellDashC(argv); dashC || err != nil {
		return true
	}
	if _, ok := cmdSlashC(argv); ok {
		return true
	}
	command := head(argv)
	switch command {
	case "eval", "source", ".":
		return true
	}
	if !interpreterHeads[command] {
		return false
	}
	for _, arg := range argv[1:] {
		lower := strings.ToLower(arg)
		switch command {
		case "python", "python3", "py":
			if lower == "-c" {
				return true
			}
		case "node", "deno", "bun":
			if lower == "-e" || lower == "-p" || lower == "--eval" || lower == "--print" || lower == "eval" {
				return true
			}
		case "perl", "ruby":
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg, "eE") {
				return true
			}
		case "php":
			if lower == "-r" {
				return true
			}
		case "pwsh", "powershell":
			if strings.HasPrefix(lower, "-c") || strings.HasPrefix(lower, "-e") || strings.HasPrefix(lower, "/c") {
				return true
			}
		}
	}
	return false
}

// shellEnablesXtrace reports `bash -x …` or `sh -o xtrace …`: the shell
// prints every expanded command, including values its environment carries.
func shellEnablesXtrace(argv []string) bool {
	if _, ok := shellOptions(head(argv)); !ok {
		return false
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			return false
		}
		if arg == "-o" && index+1 < len(argv) && argv[index+1] == "xtrace" {
			return true
		}
		if strings.ContainsRune(arg, 'x') {
			return true
		}
		if strings.ContainsRune(arg, 'c') {
			return false
		}
	}
	return false
}

// sourceEnablesXtrace reports a `set -x` or `set -o xtrace` anywhere in the
// source. Where it sits does not matter for the reading that asks.
func sourceEnablesXtrace(src string, f *syntax.File) bool {
	found := false
	syntax.Walk(f, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || found || len(call.Args) == 0 {
			return !found
		}
		var argv []string
		for _, word := range call.Args {
			literal, ok := literalText(src[word.Pos().Offset():word.End().Offset()])
			if !ok {
				literal = ""
			}
			argv = append(argv, literal)
		}
		if head(argv) != "set" {
			return true
		}
		for index, arg := range argv[1:] {
			if arg == "-o" && index+2 < len(argv) && argv[index+2] == "xtrace" {
				found = true
			}
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg, 'x') {
				found = true
			}
		}
		return !found
	})
	return found
}

// credentialStdinConsumer names programs that read a credential from stdin
// and do not print it: registry logins with --password-stdin (docker, podman,
// helm, oras, skopeo, buildah, crane, nerdctl), `gh auth login --with-token`
// (which asks under P2.gh-auth-scope for its own reason), and `gh secret set`
// without an inline body, which stores stdin as the secret's value.
func credentialStdinConsumer(argv []string) bool {
	for _, arg := range argv[1:] {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--password-stdin" || name == "--with-token" {
			return true
		}
	}
	if head(argv) == "gh" && len(argv) >= 3 && argv[1] == "secret" && argv[2] == "set" {
		for _, arg := range argv[3:] {
			name, _, _ := strings.Cut(arg, "=")
			if name == "-b" || name == "--body" || name == "-f" || name == "--env-file" {
				return false
			}
		}
		return true
	}
	return false
}

// passThroughFilters transform stdin to stdout and write nothing else, so
// the data goes wherever their output goes: `gh auth token | tr -d '\n' |
// docker login --password-stdin` is as contained as the unfiltered pipe.
// sed and awk are absent on purpose: both can write files.
var passThroughFilters = map[string]bool{
	"tr": true, "cut": true, "jq": true, "base64": true, "grep": true,
	"sort": true, "uniq": true, "fold": true, "rev": true,
}
