package actiongrant

import "fmt"

// Summary shows all input, including its quoted spelling. No redacted audit
// record can stand in for the private action the operator is authorizing.
func (r Request) Summary() string {
	return fmt.Sprintf("Repository: %s\nWorking directory: %s\nPlane: %s\nSession: %s\nTool: %s\nRule: %s\nPaths: %q\n%s:\n%s\nExact: %q (%d bytes)\nOne identical retry; expires %s\nDigest: %s", r.Action.Repo, r.Action.CWD, r.Action.Plane, r.Action.Session, r.Action.Tool, r.Action.Rule, r.Action.Paths, r.Action.Kind, r.Action.Text, r.Action.Text, len(r.Action.Text), r.Expires.Format("2006-01-02T15:04:05Z07:00"), r.Digest)
}
