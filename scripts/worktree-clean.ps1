[CmdletBinding()]
param(
    [string]$Base = "",
    [switch]$DryRun,
    [switch]$Force,
    [switch]$PruneOrphans
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (git rev-parse --show-toplevel 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $repoRoot) {
    Write-Error "worktree-clean: not inside a git repository"
    exit 2
}
$repoRoot = [System.IO.Path]::GetFullPath($repoRoot.Trim())

if (-not $Base) {
    git rev-parse --verify --quiet origin/main *> $null
    if ($LASTEXITCODE -eq 0) {
        $Base = "origin/main"
    } else {
        $Base = "main"
    }
}

git rev-parse --verify --quiet $Base *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error "worktree-clean: base ref '$Base' not found"
    exit 2
}

# Parse `git worktree list --porcelain` into entries. Index 0 is always the primary worktree.
$porcelain = @(git worktree list --porcelain)
if ($LASTEXITCODE -ne 0) {
    Write-Error "worktree-clean: failed to list worktrees"
    exit 2
}

$entries = New-Object System.Collections.Generic.List[hashtable]
$current = $null
foreach ($line in $porcelain) {
    if ($line -eq "") {
        if ($null -ne $current) {
            $entries.Add($current)
            $current = $null
        }
        continue
    }
    if ($line -match '^worktree (.+)$') {
        if ($null -ne $current) {
            $entries.Add($current)
        }
        $current = @{
            Path     = [System.IO.Path]::GetFullPath($Matches[1])
            Branch   = ""
            Detached = $false
        }
    } elseif ($null -ne $current -and $line -match '^branch refs/heads/(.+)$') {
        $current.Branch = $Matches[1]
    } elseif ($null -ne $current -and $line -eq 'detached') {
        $current.Detached = $true
    }
}
if ($null -ne $current) {
    $entries.Add($current)
}

$registeredPaths = @{}
foreach ($e in $entries) {
    $registeredPaths[$e.Path.TrimEnd('\', '/').ToLowerInvariant()] = $true
}

$hadAttention = $false

# Process linked worktrees only (skip index 0, the primary worktree).
for ($i = 1; $i -lt $entries.Count; $i++) {
    $wt = $entries[$i]
    $reason = ""
    if ($wt.Detached) {
        $reason = "detached HEAD"
    } elseif ($wt.Branch) {
        git merge-base --is-ancestor "refs/heads/$($wt.Branch)" $Base 2>$null
        if ($LASTEXITCODE -eq 0) {
            $reason = "branch '$($wt.Branch)' merged into $Base"
        }
    }

    if (-not $reason) {
        Write-Output "keep: $($wt.Path) (branch '$($wt.Branch)' has unmerged commits)"
        continue
    }

    if ($DryRun) {
        Write-Output "would remove: $($wt.Path) ($reason)"
        continue
    }

    $removeArgs = @("worktree", "remove")
    if ($Force) {
        $removeArgs += "--force"
    }
    $removeArgs += $wt.Path

    $out = & git @removeArgs 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0 -or (Test-Path -LiteralPath $wt.Path)) {
        # Windows handles can linger briefly after an agent process exits (#84); retry once.
        Start-Sleep -Seconds 2
        if (Test-Path -LiteralPath $wt.Path) {
            $out = & git @removeArgs 2>&1
            $exitCode = $LASTEXITCODE
        }
    }

    if (Test-Path -LiteralPath $wt.Path) {
        $hadAttention = $true
        Write-Output "PARTIAL REMOVAL: $($wt.Path) still exists after retry ($out)"
        Write-Output "  operator command: Remove-Item -Recurse -Force '$($wt.Path)'"
    } elseif ($exitCode -ne 0) {
        $hadAttention = $true
        Write-Output "FAILED: $($wt.Path) ($out)"
    } else {
        Write-Output "removed: $($wt.Path) ($reason)"
    }
}

# Detect partial-removal orphans under .worktrees/ and .claude/worktrees/ whose .git is gone.
$containers = @(
    (Join-Path $repoRoot ".worktrees"),
    (Join-Path (Join-Path $repoRoot ".claude") "worktrees")
)

foreach ($container in $containers) {
    if (-not (Test-Path -LiteralPath $container -PathType Container)) {
        continue
    }
    foreach ($child in Get-ChildItem -LiteralPath $container -Directory) {
        $full = [System.IO.Path]::GetFullPath($child.FullName)
        $key = $full.TrimEnd('\', '/').ToLowerInvariant()
        if ($registeredPaths.ContainsKey($key)) {
            continue
        }
        $gitMarker = Join-Path $full ".git"
        if (Test-Path -LiteralPath $gitMarker) {
            continue
        }
        if ($DryRun) {
            Write-Output "ORPHAN REMNANT (partial removal, no .git): $full"
            Write-Output "  operator command: Remove-Item -Recurse -Force '$full'"
            continue
        }
        if ($PruneOrphans) {
            try {
                Remove-Item -LiteralPath $full -Recurse -Force
                Write-Output "removed orphan remnant: $full"
            } catch {
                $hadAttention = $true
                Write-Output "PARTIAL REMOVAL: could not delete orphan $full ($($_.Exception.Message))"
                Write-Output "  operator command: Remove-Item -Recurse -Force '$full'"
            }
        } else {
            $hadAttention = $true
            Write-Output "ORPHAN REMNANT (partial removal, no .git): $full"
            Write-Output "  operator command: Remove-Item -Recurse -Force '$full'"
        }
    }
}

if (-not $DryRun) {
    git worktree prune 2>$null
}

if ($hadAttention) {
    exit 1
}
exit 0
