# ADR-0041: A secret's bare name is a secret-tier candidate for any command

## Status

Proposed (#687). Awaiting the operator's decision on the four numbered
points under "Proposed decision".

## Context

The secret tier (`P4.secret-path`) judges path candidates. A word of a shell
command becomes a candidate when it contains a separator, `~` or a drive
letter, or when the command has a reader of its own: the dedicated grammars
(`grep`, `sed`, `jq`, `yq`, `awk`, `tar`, `dd`, `find`), the bare-name reader
list (`cat`, `head`, `cp`, …) and, since #683, PowerShell's file cmdlets.

For every other command a bare word is not a candidate. This is the current,
tested behavior, not an oversight:
`TestBareFilenameReaderHintsAndUnlistedResidue` pins `cat id_rsa` as a deny
and `somenewtool id_rsa` as an allow, and calls the second "unlisted bare-name
residue". The lists are hints. A command nobody listed fails open.

Measured on `main` at `1ff0b08` (Claude plane, `Evaluate`, repository root as
working directory):

| Command | Verdict |
|---|---|
| `cat .env`, `wc -l .env`, `test -f .env`, `touch .env`, `chmod 600 .env` | deny |
| `findstr FAKE .env`, `certutil -encode .env out.txt`, `notepad .env` | allow |
| `vim .env`, `code .env`, `python3 read.py .env`, `node x.js id_rsa` | allow |
| `Compress-Archive .env out.zip`, `Invoke-Item .env`, `. Get-Content .env` | allow |
| `Get-Item .env \| Get-Content`, `'.env' \| Get-Content` | allow |
| `cat .en*`, `Get-Content *.env` | allow |
| `ls .env`, `stat .env`, `git add .env`, `git status .env` | allow |
| `rg .env` | allow |
| `rg -F .env docs` | deny |

Two things stand out. The set of programs that open a file named on their
command line is open-ended, so the lists cannot be finished; #683 was one
entry, found by accident. And the current verdicts are already uneven about
what counts as touching a secret: `test -f .env` and `touch .env` are denied
while `ls .env` and `git add .env` are allowed.

#683 also showed that a per-command exemption cannot be made safe by
guessing. The tokenizer has dropped quoting before operands are read, so the
Engine cannot tell which word a command binds where unless it owns that
command's grammar.

## Proposed decision

1. **Unlisted commands fail closed.** When a command has no reader of its
   own, every bare operand is a candidate for the secret tier. Only the
   secret tier: containment, symlink and write-target rules keep their
   current inputs. A word matters only when it matches a secret pattern, so
   commands with ordinary operands are unaffected.

2. **Known grammars keep their exemptions.** `grep`, `sed`, `jq`, `yq`,
   `awk`, `tar`, `dd` and `find` already say which words are patterns or
   programs. Those stay non-candidates: `grep -r id_rsa src` and
   `sed 's/.env/.cfg/' a.txt` remain allowed. `rg` gains a grammar of its
   own so its pattern is exempt and its paths are not; today `rg .env` and
   `rg -F .env docs` disagree.

3. **Naming a secret to a command is treated as touching it, with a short
   list of commands that only print their arguments.** `echo` and `printf`
   never open an operand and stay allowed. Everything else that names a
   secret is denied, including the metadata and version-control forms:
   `ls .env`, `stat .env`, `git add .env`, `git status .env`,
   `git check-ignore .env`. This matches what `main` already does for
   `test -f .env`, `touch .env` and `chmod 600 .env`, and it stops
   `git add .env` from staging a secret for publication.

4. **Wildcards and indirect naming.** An operand containing `*`, `?` or `[`
   is a candidate when it can match a secret's name; the check is static,
   made against the secret patterns, with no filesystem read (ADR-0012). A
   quoted literal that is the whole first stage of a pipeline
   (`'.env' | Get-Content`) and an option's attached value
   (`cat -Path:.env`) are candidates too.

## Cost, measured

A prototype of point 1 alone, with no exemptions, was run against the engine
suite and a list of ordinary commands on 2026-11-22.

It closed every bare-name row in the table above except the wildcard,
pipeline-literal and attached-value rows, which need point 4.

It flipped 13 existing tests. Eleven assert that a known grammar's pattern or
program is not a path (`TestGrepAndSedProgramsAreNotPathCandidates`, the `jq`,
`yq`, `awk` and `tar` operand tests); point 2 keeps all of them as they are.
`TestBareFilenameReaderHintsAndUnlistedResidue` flips by intent: it pins the
residue this ADR removes. `TestOpaqueSourceBoundary` flipped and has not been
analysed yet.

Ordinary commands that would newly be denied. The first column was measured
with the prototype; the second is what points 2 and 3 are designed to give
and has not been run:

| Command | Point 1 only (measured) | Points 2 and 3 (expected) |
|---|---|---|
| `echo .env`, `printf '%s\n' .env` | deny | allow |
| `grep .env notes.txt`, `grep -r .env docs` | deny | allow |
| `rg .env` | deny | allow (pattern) |
| `ls .env`, `stat .env` | deny | deny |
| `git add .env`, `git status .env`, `git check-ignore .env`, `git log -- .env` | deny | deny |
| `vim .env`, `code .env`, `notepad .env` | deny | deny |

Unchanged in every variant: `echo .env >> .gitignore`,
`echo "add .env to gitignore"`, `git commit -m "ignore .env"`,
`find . -name .env`, `git add id_rsa.pub`, `cp .env.example .env` (already
denied), and every command with no secret-shaped word.

The remaining cost is the last three rows. An agent that wants to check
whether `.env` is ignored, or list it, is denied and told why; the operator
can run the command, or allow a specific file with `secret_allow`.

## Alternatives considered

- **Keep extending the lists.** Each entry closes one command and the Engine
  still fails open for the next one. Rejected as the long-term answer; it
  remains the right fix for a single command while this decision is pending.
- **Ask instead of deny for unlisted commands.** Softer, but on a host in an
  auto-approve mode an ask becomes a deny anyway (ADR-0035), and the secret
  tier is a deny tier everywhere else. A deny with a clear reason is simpler
  to explain.
- **Exempt metadata and version-control commands.** Keeps `ls .env` and
  `git status .env` working. Rejected in the proposal because it is another
  open-ended list, `git add .env` is the case most worth stopping, and `main`
  already denies `test -f .env`. This is the point most open to the
  operator's preference.

## Stability and verification

The verdict format, rule ID (`P4.secret-path`) and Overlay keys do not
change. `secret_allow` continues to exempt a named file. The change is a
tightening: commands that were allowed become denied, never the reverse, with
the exception of `rg -F .env docs`, which point 2 would allow when `.env` is
the pattern.

Implementation would land behind tests written first: the table above as
denies, the unchanged rows as allows, and
`TestBareFilenameReaderHintsAndUnlistedResidue` rewritten to pin the new
default.
