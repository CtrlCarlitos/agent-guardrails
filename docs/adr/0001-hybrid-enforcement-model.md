# Hybrid enforcement: generated declarative floor + shared engine

We enforce one policy across planes with very different extension APIs (Claude Code
has a mature shell-hook system that can block; opencode's plugin `throw` reaches the
user not the agent, so its declarative `permission` rules are the real boundary;
Antigravity has command hooks but no in-process model). A pure-declarative approach
(compile the policy to each plane's native permission config only) cannot express the
dynamic checks — shell tokenization, the lethal-trifecta session gate, symlink-escape
resolution — so those would be lost. N native reimplementations of the matcher (the
current takumi-dream state) drift: the secret-path list is already encoded 4×.

Decision: **hybrid.** One policy definition generates each plane's native declarative
config as a *floor* that survives an engine failure, AND a single shared Engine that
every plane's hook calls for the dynamic checks. Adapters stay thin.

## Consequences

- Engine unavailable ⇒ degrade, don't brick: dynamic checks are lost, the declarative
  floor still denies `rm -rf` / secret reads / non-allowlisted egress. Session-start
  banner reports the Engine is down.
- Two things get merged into each plane's global config at install: the hook/plugin
  registration, and the generated declarative floor.
