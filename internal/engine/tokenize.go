package engine

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Simple struct {
	Argv       []string
	Redirects  []string
	Unresolved bool
}

func splitSimples(src string) ([]Simple, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
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
			raw := src[w.Pos().Offset():w.End().Offset()]
			if lit, ok := literalText(raw); ok {
				s.Argv = append(s.Argv, lit)
			} else {
				s.Argv = append(s.Argv, raw)
				s.Unresolved = true
			}
		}
		for _, r := range stmt.Redirs {
			if r.Word == nil {
				continue
			}
			raw := src[r.Word.Pos().Offset():r.Word.End().Offset()]
			if lit, ok := literalText(raw); ok {
				s.Redirects = append(s.Redirects, lit)
			} else {
				s.Redirects = append(s.Redirects, raw)
				s.Unresolved = true
			}
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
		expanded, err := stripAndUnwrap(s)
		if err != nil {
			// This statement's wrappers could not be understood. Keep it
			// unknowable so sibling statements are still evaluated.
			degraded := s
			degraded.Unresolved = true
			out = append(out, degraded)
			continue
		}
		out = append(out, expanded...)
	}
	return out, nil
}

func stripAndUnwrap(s Simple) ([]Simple, error) {
	argv := s.Argv
loop:
	for len(argv) > 0 {
		var rest []string
		var err error
		switch head(argv) {
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
	result := []Simple{{Argv: argv, Redirects: s.Redirects, Unresolved: s.Unresolved}}
	inner, err := runnerInner(argv)
	if err != nil {
		return nil, err
	}
	if inner != nil {
		result = append(result, Simple{Argv: inner, Unresolved: s.Unresolved})
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

// normalizeShellDashC re-tokenizes the literal text passed to a shell's -c flag.
func normalizeShellDashC(word string) ([]Simple, error) {
	return Normalize(word)
}

func literalText(tok string) (string, bool) {
	// Parse in argument position so assignment-shaped words such as FOO=1
	// remain complete words rather than becoming assignment AST nodes.
	f, err := syntax.NewParser().Parse(strings.NewReader(": "+tok), "")
	if err != nil {
		return "", false
	}
	if len(f.Stmts) != 1 {
		return "", false
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 2 {
		return "", false
	}
	word := call.Args[1]
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
	switch head(argv) {
	case "sh", "bash", "zsh", "dash", "ksh":
		for i := 1; i+1 < len(argv); i++ {
			if argv[i] == "-c" && argv[i+1] != "" {
				return i
			}
		}
	}
	return -1
}

func runnerInner(argv []string) ([]string, error) {
	switch head(argv) {
	case "npx", "uvx", "bunx", "make", "just":
		if len(argv) > 1 {
			return argv[1:], nil
		}
	case "docker":
		if len(argv) > 2 && (argv[1] == "run" || argv[1] == "exec") {
			i := 2
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				i++
			}
			if i+1 < len(argv) {
				return argv[i+1:], nil // skip the image/container token
			}
		}
	case "devbox", "mise", "nix":
		if len(argv) > 2 {
			return argv[2:], nil
		}
	case "busybox":
		if len(argv) == 1 {
			return nil, nil
		}
		if strings.HasPrefix(argv[1], "-") {
			return nil, fmt.Errorf("busybox: cannot determine applet from %q; failing closed", argv[1])
		}
		return argv[1:], nil
	}
	return nil, nil
}
