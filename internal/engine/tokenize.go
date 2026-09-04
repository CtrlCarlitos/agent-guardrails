package engine

import (
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

var noopWrappers = map[string]bool{
	"time": true, "nohup": true, "xargs": true,
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
		out = append(out, stripAndUnwrap(s)...)
	}
	return out, nil
}

func stripAndUnwrap(s Simple) []Simple {
	argv := s.Argv
	for len(argv) > 0 {
		head := argv[0]
		switch {
		case head == "timeout" && len(argv) >= 2:
			argv = argv[2:] // drop "timeout" + duration
		case head == "nice" && len(argv) >= 3 && argv[1] == "-n":
			argv = argv[3:]
		case head == "nice":
			argv = argv[1:]
		case noopWrappers[head]:
			argv = argv[1:]
		case head == "env":
			i := 1
			for i < len(argv) && strings.Contains(argv[i], "=") {
				i++
			}
			argv = argv[i:]
		default:
			goto done
		}
	}
done:
	if len(argv) == 0 {
		return nil
	}
	result := []Simple{{Argv: argv, Redirects: s.Redirects}}
	if inner := runnerInner(argv); inner != nil {
		result = append(result, Simple{Argv: inner})
	}
	return result
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
