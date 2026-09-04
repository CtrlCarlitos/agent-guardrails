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
