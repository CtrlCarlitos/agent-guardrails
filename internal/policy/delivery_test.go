package policy

import "testing"

func TestDeliveryPolicyIsRepositoryScopedAndValidated(t *testing.T) {
	repo := operatorRepo("delivery")
	writeOperatorConfig(t, tomlRepoKey(repo)+"\n["+"'"+repo+"'"+".delivery]\ngithub = 'owner/repo'\ngithub_id = 1\nbase = 'main'\nmethod = 'squash'\nprotected_paths = ['ci/**']\n")
	op, err := LoadOperatorConfig()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := op.DeliveryFor(repo)
	if !ok || got.GitHub != "owner/repo" || got.Method != "squash" {
		t.Fatalf("configured repository lost delivery authorization: %#v %v", got, ok)
	}
	if _, ok := op.DeliveryFor(operatorRepo("other")); ok {
		t.Fatal("delivery authorization crossed repository boundary")
	}
	if _, ok := (*OperatorConfig)(nil).DeliveryFor(repo); ok {
		t.Fatal("missing operator config authorized delivery")
	}
}

func TestDeliveryPolicyRejectsMalformedAuthority(t *testing.T) {
	for _, extra := range []string{"github = '../other'\nbase = 'main'\nmethod = 'squash'", "github = 'owner/repo'\nbase = ''\nmethod = 'squash'", "github = 'owner/repo'\nbase = 'main'\nmethod = 'admin'"} {
		t.Run(extra, func(t *testing.T) {
			repo := operatorRepo("delivery")
			writeOperatorConfig(t, "['"+repo+"'.delivery]\n"+extra+"\n")
			if _, err := LoadOperatorConfig(); err == nil {
				t.Fatal("malformed delivery policy must fail closed")
			}
		})
	}
}

func TestDeliveryPolicyRequiresStableGitHubIdentity(t *testing.T) {
	repo := operatorRepo("delivery")
	writeOperatorConfig(t, "['"+repo+"'.delivery]\ngithub = 'owner/repo'\nbase = 'main'\nmethod = 'squash'\n")
	if _, err := LoadOperatorConfig(); err == nil {
		t.Fatal("repository name alone must not authorize a different repository reusing that name")
	}
}
