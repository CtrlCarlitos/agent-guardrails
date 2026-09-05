package engine

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Simple struct {
	Argv          []string
	Redirects     []string
	ReadRedirects []string
	Unresolved    bool
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
		var args []*syntax.Word
		if stmt.Cmd != nil {
			ce, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok {
				if len(stmt.Redirs) == 0 {
					return true
				}
			} else {
				args = ce.Args
			}
		}
		if len(args) == 0 && len(stmt.Redirs) == 0 {
			return true
		}
		s := Simple{}
		for _, w := range args {
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
			read, write := false, false
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
				write = true
			case syntax.RdrIn:
				read = true
			case syntax.RdrInOut:
				read, write = true, true
			case syntax.DplOut:
				if r.N != nil {
					continue
				}
				write = true
			default:
				continue
			}
			raw := src[r.Word.Pos().Offset():r.Word.End().Offset()]
			target, literal := literalText(raw)
			if !literal {
				target = raw
				s.Unresolved = true
			}
			if r.Op == syntax.DplOut && literal && (target == "-" || allDigits(target)) {
				continue
			}
			if write {
				s.Redirects = append(s.Redirects, target)
			}
			if read {
				s.ReadRedirects = append(s.ReadRedirects, target)
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
	if len(s.Argv) == 0 {
		if len(s.Redirects) == 0 && len(s.ReadRedirects) == 0 {
			return nil, nil
		}
		return []Simple{s}, nil
	}
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
		case "setsid":
			rest, err = consumeSetsid(argv[1:])
		case "stdbuf":
			rest, err = consumeStdbuf(argv[1:])
		case "ionice":
			rest, err = consumeIonice(argv[1:])
		case "watch":
			rest, err = consumeWatch(argv[1:])
		case "chroot":
			rest, err = consumeChroot(argv[1:])
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
				argv = nil // -v/-V only locate a command; redirects still take effect
				break loop
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
		if len(s.Redirects) == 0 && len(s.ReadRedirects) == 0 {
			return nil, nil
		}
		s.Argv = argv
		return []Simple{s}, nil
	}
	result := []Simple{{Argv: argv, Redirects: s.Redirects, ReadRedirects: s.ReadRedirects, Unresolved: s.Unresolved}}
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

// consumeKnownFlags skips options belonging to a wrapper. Unknown options fail
// closed because guessing their arity could make data look like a command.
func consumeKnownFlags(name string, argv []string, known, valued map[string]bool) ([]string, error) {
	for i := 0; i < len(argv); {
		a := argv[i]
		if a == "--" {
			return argv[i+1:], nil
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return argv[i:], nil
		}
		if known[a] {
			i++
			continue
		}
		if valued[a] {
			if i+1 >= len(argv) {
				return nil, needsValue(name, a)
			}
			i += 2
			continue
		}
		if eq := strings.IndexByte(a, '='); eq >= 0 && valued[a[:eq]] {
			i++
			continue
		}
		attached := false
		for flag := range valued {
			if len(flag) == 2 && strings.HasPrefix(a, flag) && len(a) > len(flag) {
				attached = true
				break
			}
		}
		if attached {
			i++
			continue
		}
		return nil, unknownOpt(name, a)
	}
	return nil, nil
}

func consumeSetsid(argv []string) ([]string, error) {
	known := map[string]bool{
		"-f": true, "--fork": true,
		"-w": true, "--wait": true,
		"-c": true, "--ctty": true,
	}
	return consumeKnownFlags("setsid", argv, known, nil)
}

func consumeStdbuf(argv []string) ([]string, error) {
	valued := map[string]bool{
		"-i": true, "--input": true,
		"-o": true, "--output": true,
		"-e": true, "--error": true,
	}
	return consumeKnownFlags("stdbuf", argv, nil, valued)
}

func consumeIonice(argv []string) ([]string, error) {
	known := map[string]bool{"-t": true, "--ignore": true}
	valued := map[string]bool{
		"-c": true, "--class": true,
		"-n": true, "--classdata": true,
	}
	return consumeKnownFlags("ionice", argv, known, valued)
}

func consumeWatch(argv []string) ([]string, error) {
	known := map[string]bool{
		"-d": true, "--differences": true,
		"-t": true, "--no-title": true,
		"-b": true,
		"-e": true,
	}
	valued := map[string]bool{"-n": true, "--interval": true}
	return consumeKnownFlags("watch", argv, known, valued)
}

func consumeChroot(argv []string) ([]string, error) {
	valued := map[string]bool{"--userspec": true, "--groups": true}
	rest, err := consumeKnownFlags("chroot", argv, nil, valued)
	if err != nil {
		return nil, err
	}
	if len(rest) == 0 {
		return nil, fmt.Errorf("chroot: missing new-root argument; failing closed")
	}
	return rest[1:], nil
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
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "mksh", "ash":
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
