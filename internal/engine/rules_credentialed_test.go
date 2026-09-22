package engine

import (
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

func evalCred(t *testing.T, command string) policy.Verdict {
	t.Helper()
	return Evaluate(ToolCall{Plane: "claude", Tool: "Bash", NativeTool: "Bash",
		Capability: policy.CapabilityCommand, Command: command, CWD: "/repo", RepoRoot: "/repo"}, pathPol())
}

// These CLIs act with credentials the agent never reads, and their effects are
// public, irreversible or billed (#235). Same shape as the gh work: the
// authority is ambient, so the command text is the only place a gate can sit.
//
// Rule ids are per family rather than one blob, so an operator running a
// Kubernetes dev loop does not have to waive `npm publish` to do it, and so
// the per-rule verdict profile stays legible.

// Publishing a package is public and effectively irreversible -- unpublish
// windows are short or absent, and consumers may already have pulled.
func TestPublishAsks(t *testing.T) {
	for _, command := range []string{
		"npm publish",
		"npm publish --access public",
		"pnpm publish",
		"yarn npm publish",
		"cargo publish",
		"twine upload dist/*",
		"gem push mygem-1.0.gem",
	} {
		v := evalCred(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P6.publish" {
			t.Errorf("%q -> %+v, want ask/P6.publish", command, v)
		}
	}
}

// A registry push is the same act with a different artifact: consumers pull
// by tag, and a moved tag is invisible to them.
func TestRegistryPushAsks(t *testing.T) {
	for _, command := range []string{
		"docker push registry.example.com/app:latest",
		"docker buildx build --push -t registry.example.com/app:latest .",
		"podman push registry.example.com/app:latest",
		"oras push registry.example.com/app:1.0 file.txt",
	} {
		v := evalCred(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P6.publish" {
			t.Errorf("%q -> %+v, want ask/P6.publish", command, v)
		}
	}
}

// Cluster mutation is destructive and, on a cloud cluster, metered through
// node autoscaling.
func TestClusterMutationAsks(t *testing.T) {
	for _, command := range []string{
		"kubectl delete pod mypod",
		"kubectl apply -f deploy.yaml",
		"kubectl scale deployment/api --replicas=10",
		"kubectl patch deployment api -p '{}'",
		"kubectl replace -f deploy.yaml",
		"kubectl drain node-1",
		"kubectl rollout restart deployment/api",
		"helm install myrelease ./chart",
		"helm upgrade myrelease ./chart",
		"helm uninstall myrelease",
	} {
		v := evalCred(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P6.cluster-mutate" {
			t.Errorf("%q -> %+v, want ask/P6.cluster-mutate", command, v)
		}
	}
}

// A local cluster is routine work. The context has to be stated explicitly --
// if it cannot be determined from the command text, the safe reading is that
// it might be production.
func TestLocalClusterContextStaysAllow(t *testing.T) {
	for _, command := range []string{
		"kubectl --context kind-dev delete pod mypod",
		"kubectl --context=minikube apply -f deploy.yaml",
		"kubectl --context docker-desktop delete pod x",
		"kubectl --context k3d-local apply -f x.yaml",
		"kubectl --context rancher-desktop delete pod x",
	} {
		if v := evalCred(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: a local cluster is routine", command, v)
		}
	}
	// A named non-local context is not routine.
	if v := evalCred(t, "kubectl --context prod-eu delete pod x"); v.Decision != policy.Ask {
		t.Errorf("named production context -> %+v, want ask", v)
	}
}

// Cloud CLIs are the canonical runaway-bill path. Enumerating every mutating
// verb across aws/gcloud/az is not tractable, so the read verbs are the
// allowlist and anything else asks -- unknown means ask, which is the
// direction a billing mistake should fail in.
func TestCloudMutationAsks(t *testing.T) {
	for _, command := range []string{
		"aws ec2 run-instances --image-id ami-123",
		"aws s3 rb s3://bucket --force",
		"gcloud compute instances create vm-1",
		"az vm create --name vm1 --resource-group rg",
		"doctl compute droplet create web-1",
		"flyctl deploy",
		"terraform apply",
		"terraform destroy",
		"pulumi up",
		"pulumi destroy",
	} {
		v := evalCred(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P6.cloud-mutate" {
			t.Errorf("%q -> %+v, want ask/P6.cloud-mutate", command, v)
		}
	}
}

// Deploy CLIs put a change in front of the public.
func TestDeployAsks(t *testing.T) {
	for _, command := range []string{
		"vercel --prod",
		"netlify deploy --prod",
		"wrangler deploy",
		"wrangler publish",
		"firebase deploy",
		"supabase db push",
	} {
		v := evalCred(t, command)
		if v.Decision != policy.Ask || v.RuleID != "P6.deploy" {
			t.Errorf("%q -> %+v, want ask/P6.deploy", command, v)
		}
	}
}

// The read twins. Every one of these shares a binary with a mutation above,
// so a rule that keys on the binary rather than the verb shows up here. This
// is the test that keeps the rule usable -- these are how people inspect the
// systems they are about to change.
func TestCredentialedReadsStayAllow(t *testing.T) {
	for _, command := range []string{
		"npm view express",
		"npm ls",
		"cargo search serde",
		"docker pull alpine:3",
		"docker images",
		"podman images",
		"kubectl get pods",
		"kubectl describe pod mypod",
		"kubectl logs mypod",
		"kubectl config get-contexts",
		"helm list",
		"helm status myrelease",
		"aws s3 ls",
		"aws ec2 describe-instances",
		"aws sts get-caller-identity",
		"gcloud compute instances list",
		"gcloud projects describe my-project",
		"az vm list",
		"az account show",
		"terraform plan",
		"terraform show",
		"terraform validate",
		"pulumi preview",
		"pulumi stack ls",
		"vercel ls",
		"netlify status",
		"wrangler whoami",
		"firebase projects:list",
	} {
		if v := evalCred(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: reading is not mutating", command, v)
		}
	}
}

// --dry-run means the CLI guarantees no side effect, so the gate has nothing
// to protect.
func TestDryRunStaysAllow(t *testing.T) {
	for _, command := range []string{
		"kubectl apply -f deploy.yaml --dry-run=client",
		"kubectl delete pod x --dry-run=server",
		"helm upgrade myrelease ./chart --dry-run",
		"helm install myrelease ./chart --dry-run",
		"npm publish --dry-run",
	} {
		if v := evalCred(t, command); v.Decision != policy.Allow {
			t.Errorf("%q -> %+v, want allow: --dry-run has no side effect", command, v)
		}
	}
}

// Wrapper forms reach the same binary. `npx` and `pnpm dlx` additionally
// fetch it first, which is why they are worth naming.
func TestWrapperFormsDoNotEvade(t *testing.T) {
	for _, command := range []string{
		"npx vercel --prod",
		"pnpm dlx wrangler deploy",
		"sh -c 'npm publish'",
	} {
		if v := evalCred(t, command); v.Decision != policy.Ask {
			t.Errorf("%q -> %+v, want ask: a wrapper reaches the same binary", command, v)
		}
	}
}

// The classifier must not reach commands that merely share a word.
func TestCredentialedClassifierStaysInItsLane(t *testing.T) {
	for _, command := range []string{
		"echo npm publish",
		"git push origin feature-branch",
		"grep -r publish ./src",
	} {
		v := evalCred(t, command)
		if v.RuleID == "P6.publish" || v.RuleID == "P6.deploy" || v.RuleID == "P6.cloud-mutate" {
			t.Errorf("%q -> %+v, want no credentialed-CLI verdict", command, v)
		}
	}
}
