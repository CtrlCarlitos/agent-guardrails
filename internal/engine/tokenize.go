package engine

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Simple struct {
	Argv      []string
	Redirects []string
}

func splitSimples(src string) ([]Simple, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	printer := syntax.NewPrinter()
	var out []Simple
	syntax.Walk(f, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		ce, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		s := Simple{}
		for _, w := range ce.Args {
			var b strings.Builder
			_ = printer.Print(&b, w)
			s.Argv = append(s.Argv, b.String())
		}
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			var b strings.Builder
			_ = printer.Print(&b, r.Word)
			s.Redirects = append(s.Redirects, b.String())
		}
		out = append(out, s)
		return true
	})
	return out, nil
}

// Normalize returns every command that will actually execute, with no-op
// wrappers stripped and argument-executing runners unwrapped.
func Normalize(command string) ([]Simple, error) {
	base, err := splitSimples(command)
	if err != nil {
		return nil, err
	}
	var out []Simple
	for _, s := range base {
		stripped, err := stripAndUnwrap(s)
		if err != nil {
			return nil, err
		}
		out = append(out, stripped...)
	}
	return out, nil
}

func stripAndUnwrap(s Simple) ([]Simple, error) {
	argv := s.Argv
loop:
	for len(argv) > 0 {
		var rest []string
		var err error
		switch head := argv[0]; head {
		case "env":
			rest, err = consumeEnv(argv[1:])
		case "timeout":
			rest, err = consumeTimeout(argv[1:])
		case "nice":
			rest, err = consumeNice(argv[1:])
		case "nohup":
			rest, err = consumeNoFlags("nohup", argv[1:])
		case "xargs":
			rest, err = consumeXargs(argv[1:])
		case "exec":
			rest, err = consumeExec(argv[1:])
		case "command":
			var none bool
			rest, none, err = consumeCommand(argv[1:])
			if err == nil && none {
				return nil, nil // -v/-V only locate a command; nothing executes
			}
		case "time", "eval", "builtin":
			rest = argv[1:]
		default:
			break loop
		}
		if err != nil {
			return nil, err
		}
		argv = rest
	}
	if len(argv) == 0 {
		return nil, nil
	}
	result := []Simple{{Argv: argv, Redirects: s.Redirects}}
	if inner := runnerInner(argv); inner != nil {
		result = append(result, Simple{Argv: inner})
	}
	if dashC := shellDashC(argv); dashC != -1 {
		inner, err := normalizeShellDashC(argv[dashC+1])
		if err != nil {
			return nil, err
		}
		result = append(result, inner...)
	}
	return result, nil
}

// normalizeShellDashC re-tokenizes a shell -c word: quoted and escaped
// spellings that hide the executed command are reduced to their literal text
// first. Words with expansions cannot be resolved statically, so they yield
// nothing (the outer shell simple is still evaluated on its own).
func normalizeShellDashC(word string) ([]Simple, error) {
	lit, ok := literalText(word)
	if !ok {
		return nil, nil
	}
	return Normalize(lit)
}

func literalText(tok string) (string, bool) {
	f, err := syntax.NewParser().Parse(strings.NewReader(tok), "")
	if err != nil {
		return "", false
	}
	var word *syntax.Word
	syntax.Walk(f, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok && word == nil {
			word = w
			return false
		}
		return true
	})
	if word == nil {
		return "", false
	}
	var b strings.Builder
	for _, p := range word.Parts {
		switch part := p.(type) {
		case *syntax.Lit:
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, dp := range part.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func unknownOpt(wrapper, tok string) error {
	return fmt.Errorf("%s: unrecognized option %q; failing closed", wrapper, tok)
}

func needsValue(wrapper, tok string) error {
	return fmt.Errorf("%s: option %q requires a value; failing closed", wrapper, tok)
}

func consumeEnv(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return argv[i+1:], nil
		case a == "-i" || a == "-v" || a == "-0":
			i++
		case a == "-u":
			if i+1 >= len(argv) {
				return nil, needsValue("env", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("env", a)
		case strings.Contains(a, "="):
			i++
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeTimeout(argv []string) ([]string, error) {
	i := 0
	gotDuration := false
	for i < len(argv) {
		a := argv[i]
		if !strings.HasPrefix(a, "-") {
			if !gotDuration {
				gotDuration = true
				i++
				continue
			}
			return argv[i:], nil
		}
		switch {
		case a == "-k" || a == "-s":
			if i+1 >= len(argv) {
				return nil, needsValue("timeout", a)
			}
			i += 2
		case a == "-v" || a == "--preserve-status" || a == "--foreground":
			i++
		default:
			return nil, unknownOpt("timeout", a)
		}
	}
	return nil, nil
}

func consumeNice(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-n":
			if i+1 >= len(argv) {
				return nil, needsValue("nice", a)
			}
			i += 2
		case len(a) > 1 && strings.HasPrefix(a, "-") && allDigits(a[1:]):
			i++
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("nice", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func consumeNoFlags(wrapper string, argv []string) ([]string, error) {
	if len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
		return nil, unknownOpt(wrapper, argv[0])
	}
	return argv, nil
}

func consumeXargs(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-0" || a == "-r" || a == "-t" || a == "-p":
			i++
		case a == "-n" || a == "-I" || a == "-P" || a == "-E" || a == "-d":
			if i+1 >= len(argv) {
				return nil, needsValue("xargs", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("xargs", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeExec(argv []string) ([]string, error) {
	i := 0
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-a":
			if i+1 >= len(argv) {
				return nil, needsValue("exec", a)
			}
			i += 2
		case strings.HasPrefix(a, "-"):
			return nil, unknownOpt("exec", a)
		default:
			return argv[i:], nil
		}
	}
	return nil, nil
}

func consumeCommand(argv []string) (rest []string, none bool, err error) {
	i := 0
	locate := false
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "-v" || a == "-V":
			locate = true
			i++
		case strings.HasPrefix(a, "-"):
			return nil, false, unknownOpt("command", a)
		default:
			if locate {
				return nil, true, nil
			}
			return argv[i:], false, nil
		}
	}
	return nil, true, nil
}

func shellDashC(argv []string) int {
	switch argv[0] {
	case "sh", "bash", "zsh", "dash", "ksh":
		for i := 1; i+1 < len(argv); i++ {
			if argv[i] == "-c" && argv[i+1] != "" {
				return i
			}
		}
	}
	return -1
}

func runnerInner(argv []string) []string {
	switch argv[0] {
	case "npx", "uvx", "bunx", "make", "just":
		if len(argv) > 1 {
			return argv[1:]
		}
	case "docker":
		if len(argv) > 2 && (argv[1] == "run" || argv[1] == "exec") {
			i := 2
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				i++
			}
			if i+1 < len(argv) {
				return argv[i+1:] // skip the image/container token
			}
		}
	case "devbox", "mise", "nix":
		if len(argv) > 2 {
			return argv[2:]
		}
	}
	return nil
}
