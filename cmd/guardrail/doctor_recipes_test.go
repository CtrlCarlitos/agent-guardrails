package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func TestDoctorRecipeStatusShowsEffectiveSupport(t *testing.T) {
	var out bytes.Buffer
	printRecipeStatus(&policy.Policy{}, &out)
	text := out.String()
	for _, want := range []string{
		"recipes per-edit: go, python, js-ts, rust",
		"recipes odoo: disabled (opt in with [recipes.odoo])",
		"recipes session-completion claude: none installed (Stop/SubagentStop is the only supported trigger)",
		"recipes session-completion opencode: unsupported",
		"recipes session-completion antigravity: unsupported",
		"recipes session-completion codex: unsupported",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("doctor recipe status missing %q:\n%s", want, text)
		}
	}
}

func TestDoctorRecipeStatusShowsOdooConfigurationWithoutClaimingExecution(t *testing.T) {
	pol := &policy.Policy{Recipes: policy.RecipeConfig{Odoo: &policy.OdooRecipeConfig{
		Module: "sale_guardrail", TestDatabase: "guardrail_test", RelaxNG: "schema/import_xml.rng",
	}}}
	var out bytes.Buffer
	printRecipeStatus(pol, &out)
	text := out.String()
	if !strings.Contains(text, "recipes odoo: configured (module=sale_guardrail, test_database=guardrail_test, relax_ng=schema/import_xml.rng); execution not installed") {
		t.Fatal(text)
	}
}
