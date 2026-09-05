package engine

import "testing"

func TestGitSubcommandSkipsValueFlags(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"git", "push"}, "push"},
		{[]string{"git", "-C", ".", "push"}, "push"},
		{[]string{"git", "-c", "user.email=x@y", "push"}, "push"},
		{[]string{"git", "-C", "/tmp/other-repo", "-c", "a=b", "push", "--force"}, "push"},
		{[]string{"git", "-c", "a=1", "-c", "b=2", "config", "user.email", "x"}, "config"},
		{[]string{"git", "--git-dir=/tmp/x", "push"}, "push"},
		{[]string{"git", "-p", "log"}, "log"},
		{[]string{"git"}, ""},
		{[]string{"git", "-C"}, ""}, // malformed (missing value) must not panic or misparse
	}
	for _, c := range cases {
		if got := gitSubcommand(c.argv); got != c.want {
			t.Errorf("gitSubcommand(%v) = %q, want %q", c.argv, got, c.want)
		}
	}
}

func TestGitSubcommandHelpersConsumeValueGlobalsConsistently(t *testing.T) {
	cases := [][]string{
		{"git", "-C", "/r", "remote", "add"},
		{"git", "-C/r", "remote", "add"},
		{"git", "-c", "a=b", "remote", "add"},
		{"git", "-ca=b", "remote", "add"},
		{"git", "--namespace", "ns", "remote", "add"},
		{"git", "--namespace=ns", "remote", "add"},
		{"git", "--git-dir", "/r/.git", "remote", "add"},
		{"git", "--git-dir=/r/.git", "remote", "add"},
		{"git", "--work-tree", "/r", "remote", "add"},
		{"git", "--work-tree=/r", "remote", "add"},
		{"git", "--exec-path", "/x", "remote", "add"},
		{"git", "--exec-path=/x", "remote", "add"},
		{"git", "--attr-source", "HEAD", "remote", "add"},
		{"git", "--attr-source=HEAD", "remote", "add"},
		{"git", "--super-prefix", "x", "remote", "add"},
		{"git", "--super-prefix=x", "remote", "add"},
		{"git", "--config-env", "k=V", "remote", "add"},
		{"git", "--config-env=k=V", "remote", "add"},
	}
	for _, argv := range cases {
		if got := gitSubcommand(argv); got != "remote" {
			t.Errorf("gitSubcommand(%v) = %q, want remote", argv, got)
		}
		if got := gitSubcommandArg(argv); got != "add" {
			t.Errorf("gitSubcommandArg(%v) = %q, want add", argv, got)
		}
	}
}
