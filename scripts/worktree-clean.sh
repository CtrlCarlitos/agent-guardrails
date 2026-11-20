#!/usr/bin/env bash
set -euo pipefail

BASE=""
DRY_RUN=0
FORCE=0
PRUNE_ORPHANS=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base)
      shift
      if [ "$#" -eq 0 ]; then
        echo "worktree-clean: --base requires a ref" >&2
        exit 2
      fi
      BASE="$1"
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    --force)
      FORCE=1
      ;;
    --prune-orphans)
      PRUNE_ORPHANS=1
      ;;
    -h|--help)
      echo "usage: $0 [--base <ref>] [--dry-run] [--force] [--prune-orphans]"
      exit 0
      ;;
    *)
      echo "worktree-clean: unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$REPO_ROOT" ]; then
  echo "worktree-clean: not inside a git repository" >&2
  exit 2
fi

if [ -z "$BASE" ]; then
  if git rev-parse --verify --quiet origin/main >/dev/null 2>&1; then
    BASE="origin/main"
  else
    BASE="main"
  fi
fi

if ! git rev-parse --verify --quiet "$BASE" >/dev/null 2>&1; then
  echo "worktree-clean: base ref '$BASE' not found" >&2
  exit 2
fi

WT_PATHS=()
WT_BRANCHES=()
WT_DETACHED=()

cur_path=""
cur_branch=""
cur_detached=0

flush_entry() {
  if [ -n "$cur_path" ]; then
    WT_PATHS+=("$cur_path")
    WT_BRANCHES+=("$cur_branch")
    WT_DETACHED+=("$cur_detached")
    cur_path=""
    cur_branch=""
    cur_detached=0
  fi
}

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    "")
      flush_entry
      ;;
    "worktree "*)
      flush_entry
      cur_path="${line#worktree }"
      ;;
    "branch refs/heads/"*)
      cur_branch="${line#branch refs/heads/}"
      ;;
    "detached")
      cur_detached=1
      ;;
  esac
done < <(git worktree list --porcelain)
flush_entry

is_registered() {
  local candidate="$1"
  local p
  for p in "${WT_PATHS[@]}"; do
    if [ "$p" = "$candidate" ]; then
      return 0
    fi
  done
  return 1
}

HAD_ATTENTION=0

# Process linked worktrees only (skip index 0, the primary worktree).
for ((i = 1; i < ${#WT_PATHS[@]}; i++)); do
  wt_path="${WT_PATHS[$i]}"
  wt_branch="${WT_BRANCHES[$i]}"
  wt_detached="${WT_DETACHED[$i]}"
  reason=""

  if [ "$wt_detached" -eq 1 ]; then
    reason="detached HEAD"
  elif [ -n "$wt_branch" ] && git merge-base --is-ancestor "refs/heads/$wt_branch" "$BASE" 2>/dev/null; then
    reason="branch '$wt_branch' merged into $BASE"
  fi

  if [ -z "$reason" ]; then
    echo "keep: $wt_path (branch '$wt_branch' has unmerged commits)"
    continue
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "would remove: $wt_path ($reason)"
    continue
  fi

  remove_args=(worktree remove)
  if [ "$FORCE" -eq 1 ]; then
    remove_args+=(--force)
  fi
  remove_args+=("$wt_path")

  set +e
  out="$(git "${remove_args[@]}" 2>&1)"
  rc=$?
  set -e

  if [ "$rc" -ne 0 ] || [ -e "$wt_path" ]; then
    sleep 2
    if [ -e "$wt_path" ]; then
      set +e
      out="$(git "${remove_args[@]}" 2>&1)"
      rc=$?
      set -e
    fi
  fi

  if [ -e "$wt_path" ]; then
    HAD_ATTENTION=1
    echo "PARTIAL REMOVAL: $wt_path still exists after retry ($out)"
    echo "  operator command: rm -rf '$wt_path'"
  elif [ "$rc" -ne 0 ]; then
    HAD_ATTENTION=1
    echo "FAILED: $wt_path ($out)"
  else
    echo "removed: $wt_path ($reason)"
  fi
done

for container in "$REPO_ROOT/.worktrees" "$REPO_ROOT/.claude/worktrees"; do
  [ -d "$container" ] || continue
  for child in "$container"/*; do
    [ -d "$child" ] || continue
    if is_registered "$child"; then
      continue
    fi
    if [ -e "$child/.git" ]; then
      continue
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "ORPHAN REMNANT (partial removal, no .git): $child"
      echo "  operator command: rm -rf '$child'"
      continue
    fi
    if [ "$PRUNE_ORPHANS" -eq 1 ]; then
      if rm -rf "$child"; then
        echo "removed orphan remnant: $child"
      else
        HAD_ATTENTION=1
        echo "PARTIAL REMOVAL: could not delete orphan $child"
        echo "  operator command: rm -rf '$child'"
      fi
    else
      HAD_ATTENTION=1
      echo "ORPHAN REMNANT (partial removal, no .git): $child"
      echo "  operator command: rm -rf '$child'"
    fi
  done
done

if [ "$DRY_RUN" -eq 0 ]; then
  git worktree prune 2>/dev/null || true
fi

if [ "$HAD_ATTENTION" -ne 0 ]; then
  exit 1
fi
exit 0
