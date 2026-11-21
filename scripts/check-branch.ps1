[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Base = "",
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$IgnoredArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

git rev-parse --git-dir *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "check-branch: not inside a git repository"
    exit 2
}

if (-not $Base) {
    foreach ($candidate in @("origin/main", "main", "origin/master", "master")) {
        git rev-parse --verify --quiet $candidate *> $null
        if ($LASTEXITCODE -eq 0) {
            $Base = $candidate
            break
        }
    }
    if (-not $Base) {
        Write-Error "check-branch: could not find base ref (tried origin/main, main, origin/master, master)"
        exit 2
    }
}

git rev-parse --verify --quiet $Base *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "check-branch: base ref '$Base' not found"
    exit 2
}

$branch = (git symbolic-ref --quiet --short HEAD 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $branch) {
    exit 0
}
$branch = $branch.Trim()
$baseShort = ($Base -split '/')[-1]

if ($branch -eq $Base -or $branch -eq $baseShort -or $branch -eq "main" -or $branch -eq "master") {
    exit 0
}

function Fail-Stale {
    param(
        [string]$Reason,
        [string[]]$Unmerged = @()
    )
    [Console]::Error.WriteLine("check-branch: branch '$branch' appears to be already merged into $Base ($Reason).")
    [Console]::Error.WriteLine("This branch is stale. Create a fresh branch from ${Base}:")
    [Console]::Error.WriteLine("  git checkout -b <new-branch-name> $Base")
    if ($Unmerged.Count -gt 0) {
        [Console]::Error.WriteLine("Then rescue your unmerged commit(s) onto the new branch:")
        [Console]::Error.WriteLine("  git cherry-pick $($Unmerged -join ' ')")
    }
    exit 1
}

# 1. Direct ancestor check (regular merge or branch with no new commits since base).
git merge-base --is-ancestor HEAD $Base 2>$null
if ($LASTEXITCODE -eq 0) {
    Fail-Stale -Reason "HEAD is already reachable from $Base"
}

# 2. Remote tracking branch deleted after merge ([gone]).
$track = (git for-each-ref --format="%(upstream:track)" "refs/heads/$branch" 2>$null)
if ($LASTEXITCODE -eq 0 -and $track -and $track.Trim() -eq "[gone]") {
    $unmerged = New-Object System.Collections.Generic.List[string]
    foreach ($line in @(git cherry $Base HEAD 2>$null)) {
        if ($line -match '^\+ ([0-9a-fA-F]+)') {
            $unmerged.Add($Matches[1])
        }
    }
    Fail-Stale -Reason "upstream tracking branch is gone" -Unmerged $unmerged.ToArray()
}

# 3. Single-commit squash-merge or cherry-pick via patch-ID (`git cherry`).
$hasApplied = $false
$cherryUnmerged = New-Object System.Collections.Generic.List[string]
foreach ($line in @(git cherry $Base HEAD 2>$null)) {
    if ($line -match '^- ') {
        $hasApplied = $true
    } elseif ($line -match '^\+ ([0-9a-fA-F]+)') {
        $cherryUnmerged.Add($Matches[1])
    }
}
if ($hasApplied) {
    Fail-Stale -Reason "commits on this branch are already applied on $Base" -Unmerged $cherryUnmerged.ToArray()
}

# 4. Multi-commit squash-merge check: compare synthetic squashed trees along
# merge-base..HEAD against $Base using `git cherry`.
$mergeBase = (git merge-base $Base HEAD 2>$null)
if ($LASTEXITCODE -eq 0 -and $mergeBase) {
    $mergeBase = $mergeBase.Trim()
    $commits = @(git rev-list --first-parent --max-count=30 "${mergeBase}..HEAD" 2>$null)
    foreach ($commitOid in $commits) {
        if (-not $commitOid) { continue }
        $commitOid = $commitOid.Trim()
        $squashOid = (git commit-tree "${commitOid}^{tree}" -p $mergeBase -m "check-branch squash check" 2>$null)
        if ($LASTEXITCODE -ne 0 -or -not $squashOid) { continue }
        $squashOid = $squashOid.Trim()
        $cherryLine = (git cherry $Base $squashOid 2>$null)
        if ($cherryLine -and $cherryLine.Trim().StartsWith("- ")) {
            $extra = New-Object System.Collections.Generic.List[string]
            foreach ($extraOid in @(git rev-list --reverse "${commitOid}..HEAD" 2>$null)) {
                if ($extraOid -and $extraOid.Trim()) {
                    $extra.Add($extraOid.Trim())
                }
            }
            Fail-Stale -Reason "cumulative diff matches a squash-merge commit on $Base" -Unmerged $extra.ToArray()
        }
    }
}

exit 0
