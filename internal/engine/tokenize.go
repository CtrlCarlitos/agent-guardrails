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
