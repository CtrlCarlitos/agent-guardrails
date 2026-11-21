#!/usr/bin/env bash
set -euo pipefail

BASE=""

usage() {
  cat <<'EOF'
usage: check-branch.sh [--base <ref>]

Checks whether the current git branch appears to have already been merged
(including squash-merged) into the base branch, so you do not accidentally
commit onto or push a stale branch.

Can also be installed directly as a git pre-push hook:
  cp scripts/check-branch.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base)
      shift
      if [ "$#" -eq 0 ]; then
        echo "check-branch: --base requires a ref" >&2
        exit 2
      fi
      BASE="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "check-branch: unknown option: $1" >&2
      exit 2
      ;;
    *)
      # Ignore positional arguments (e.g., <remote> <url> passed by git pre-push).
      ;;
  esac
  shift
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "check-branch: not inside a git repository" >&2
  exit 2
fi

if [ -z "$BASE" ]; then
  if git rev-parse --verify --quiet origin/main >/dev/null 2>&1; then
    BASE="origin/main"
  elif git rev-parse --verify --quiet main >/dev/null 2>&1; then
    BASE="main"
  elif git rev-parse --verify --quiet origin/master >/dev/null 2>&1; then
    BASE="origin/master"
  elif git rev-parse --verify --quiet master >/dev/null 2>&1; then
    BASE="master"
  else
    echo "check-branch: could not find base ref (tried origin/main, main, origin/master, master)" >&2
    exit 2
  fi
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null 2>&1; then
  echo "check-branch: base ref '$BASE' not found" >&2
  exit 2
fi

BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
BASE_SHORT="${BASE##*/}"

# Allow working directly on the base branch or detached HEAD.
if [ -z "$BRANCH" ] || [ "$BRANCH" = "$BASE" ] || [ "$BRANCH" = "$BASE_SHORT" ] || [ "$BRANCH" = "main" ] || [ "$BRANCH" = "master" ]; then
  exit 0
fi

fail_stale() {
  local reason="$1"
  local unmerged="${2:-}"

  echo "check-branch: branch '$BRANCH' appears to be already merged into $BASE ($reason)." >&2
  echo "This branch is stale. Create a fresh branch from $BASE:" >&2
  echo "  git checkout -b <new-branch-name> $BASE" >&2
  if [ -n "$unmerged" ]; then
    echo "Then rescue your unmerged commit(s) onto the new branch:" >&2
    echo "  git cherry-pick $unmerged" >&2
  fi
  exit 1
}

# 1. Direct ancestor check (regular merge or branch with no new commits since base).
if git merge-base --is-ancestor HEAD "$BASE" 2>/dev/null; then
  fail_stale "HEAD is already reachable from $BASE"
fi

# 2. Remote tracking branch deleted after merge ([gone]).
TRACK="$(git for-each-ref --format='%(upstream:track)' "refs/heads/$BRANCH" 2>/dev/null || true)"
if [ "$TRACK" = "[gone]" ]; then
  unmerged=""
  while IFS= read -r line; do
    case "$line" in
      "+ "*)
        unmerged="${unmerged:+${unmerged} }${line#+ }"
        ;;
    esac
  done < <(git cherry "$BASE" HEAD 2>/dev/null || true)
  fail_stale "upstream tracking branch is gone" "$unmerged"
fi

# 3. Single-commit squash-merge or cherry-pick via patch-ID (`git cherry`).
has_applied=0
cherry_unmerged=""
while IFS= read -r line; do
  case "$line" in
    "- "*)
      has_applied=1
      ;;
    "+ "*)
      cherry_unmerged="${cherry_unmerged:+${cherry_unmerged} }${line#+ }"
      ;;
  esac
done < <(git cherry "$BASE" HEAD 2>/dev/null || true)

if [ "$has_applied" -eq 1 ]; then
  fail_stale "commits on this branch are already applied on $BASE" "$cherry_unmerged"
fi

# 4. Multi-commit squash-merge check: compare synthetic squashed trees along
# merge-base..HEAD against $BASE using `git cherry`.
MERGE_BASE="$(git merge-base "$BASE" HEAD 2>/dev/null || true)"
if [ -n "$MERGE_BASE" ]; then
  while IFS= read -r commit_oid; do
    [ -n "$commit_oid" ] || continue
    squash_oid="$(git commit-tree "${commit_oid}^{tree}" -p "$MERGE_BASE" -m "check-branch squash check" 2>/dev/null || true)"
    [ -n "$squash_oid" ] || continue
    cherry_line="$(git cherry "$BASE" "$squash_oid" 2>/dev/null || true)"
    case "$cherry_line" in
      "- "*)
        unmerged=""
        while IFS= read -r extra_oid; do
          [ -n "$extra_oid" ] || continue
          unmerged="${unmerged:+${unmerged} }${extra_oid}"
        done < <(git rev-list --reverse "${commit_oid}..HEAD" 2>/dev/null || true)
        fail_stale "cumulative diff matches a squash-merge commit on $BASE" "$unmerged"
        ;;
    esac
  done < <(git rev-list --first-parent --max-count=30 "${MERGE_BASE}..HEAD" 2>/dev/null || true)
fi

exit 0
