package recipe

import "testing"

func TestForFile(t *testing.T) {
	cases := map[string]string{
		"main.go":       "go",
		"app.py":        "python",
		"index.ts":      "js-ts",
		"component.tsx": "js-ts",
		"lib.rs":        "rust",
	}
	for file, want := range cases {
		r, ok := ForFile(file)
		if !ok || r.Name != want {
			t.Errorf("ForFile(%q) = %+v,%v; want %q", file, r, ok, want)
		}
	}
	if _, ok := ForFile("README.md"); ok {
		t.Error("README.md should have no recipe")
	}
}

func TestRegistryNoExtensionCollisions(t *testing.T) {
	seen := map[string]string{}
	for _, r := range Registry {
		for _, ext := range r.Extensions {
			if owner, dup := seen[ext]; dup {
				t.Errorf("extension %q claimed by both %q and %q", ext, owner, r.Name)
			}
			seen[ext] = r.Name
		}
	}
}
