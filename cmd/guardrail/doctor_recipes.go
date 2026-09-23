package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
	"github.com/CtrlCarlitos/agent-guardrails/internal/recipe"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func printRecipeStatus(pol *policy.Policy, stdout io.Writer) {
	perEdit := recipe.NamesWithPerEdit()
	if len(perEdit) == 0 {
		fmt.Fprintln(stdout, "recipes per-edit: none installed")
	} else {
		fmt.Fprintf(stdout, "recipes per-edit: %s\n", strings.Join(perEdit, ", "))
	}

	if pol == nil || pol.Recipes.Odoo == nil {
		fmt.Fprintln(stdout, "recipes odoo: disabled (opt in with [recipes.odoo])")
	} else {
		odoo := pol.Recipes.Odoo
		fmt.Fprintf(stdout, "recipes odoo: enabled (per-edit + claude session-completion; module=%s, test_database=%s, relax_ng=%s)\n",
			safetext.SingleLine(odoo.Module), safetext.SingleLine(odoo.TestDatabase), safetext.SingleLine(odoo.RelaxNG))
	}

	session := recipe.NamesWithSession()
	if len(session) == 0 {
		fmt.Fprintln(stdout, "recipes session-completion claude: none installed (Stop/SubagentStop is the only supported trigger)")
	} else {
		fmt.Fprintf(stdout, "recipes session-completion claude: %s (Stop/SubagentStop)\n", strings.Join(session, ", "))
	}
	for _, plane := range []string{"opencode", "antigravity", "codex"} {
		fmt.Fprintf(stdout, "recipes session-completion %s: unsupported\n", plane)
	}
}
