// Package genconfig translates a merged policy into each plane's native
// declarative config (the "declarative floor") and merges it into that plane's
// settings file.
package genconfig

// Fragment is a JSON-shaped config fragment ready to be merged into a plane's
// settings file.
type Fragment = map[string]any

// bashDenyGlobs is the curated coarse floor for P1 deny-tier shell commands.
// Intentionally not exhaustive — Claude's argument-glob matching is fragile and
// the Engine is the real check; this only has to catch the worst cases when the
// Engine binary is missing.
func bashDenyGlobs() []string {
	return []string{
		"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(rm -r -f *)", "Bash(rm -f -r *)",
		"Bash(dd *)",
		"Bash(mkfs*)", "Bash(wipefs *)",
		"Bash(shred *)", "Bash(srm *)",
		"Bash(sudo *)", "Bash(su *)", "Bash(su)", "Bash(doas *)",
		"Bash(git push --force*)", "Bash(git push -f*)",
		"Bash(git clean -f*)", "Bash(git clean -xf*)", "Bash(git clean -fx*)",
		"Bash(git clean -df*)", "Bash(git clean -fd*)",
		"Bash(docker compose down*)",
		"Bash(docker system prune*)", "Bash(docker volume prune*)", "Bash(docker network prune*)",
	}
}

// bashAskGlobs is the curated coarse floor for P1 ask-tier shell commands.
func bashAskGlobs() []string {
	return []string{
		"Bash(chmod -R *)", "Bash(chmod 777 *)", "Bash(chmod -R 777 *)",
		"Bash(chown -R *)",
		"Bash(truncate *)",
		"Bash(kill -9 *)", "Bash(killall *)", "Bash(pkill *)",
		"Bash(find * -delete)",
	}
}
