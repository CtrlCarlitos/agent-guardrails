# Hermetic harness for install.ps1: stages a release from $env:DIST into a
# temp directory and runs every case with `-BaseUrl <tmp>\releases -NoSetup`.
# Prints PASS:/FAIL:/SKIP: per case and exits 1 on any FAIL.
# `make installer-test-windows`.
#
# On Windows every case runs. Under pwsh on Linux or macOS only
# parses-under-windows-powershell-syntax runs; the behavioural cases print
# SKIP: and run on the Windows CI runner.
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $here)
$InstallPs1 = $env:INSTALL_PS1
if (-not $InstallPs1) { $InstallPs1 = Join-Path $repoRoot 'install.ps1' }
$Version = $env:VERSION
if (-not $Version) { $Version = 'v0.0.0-ci' }

$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ((Test-Path Variable:IsWindows) -and $IsWindows)

$script:fails = 0
# A case prints diagnostics with Write-Host (never to the output stream, so
# every helper's only output is its verdict) and returns $true or $false.
function Check([string]$Label, [scriptblock]$Case) {
	$res = @()
	try { $res = @(& $Case) } catch { Write-Host "  threw: $_"; $res = @($false) }
	$ok = ($res.Count -eq 1) -and ($res[0] -is [bool]) -and $res[0]
	if ($res.Count -ne 1) { Write-Host "  case returned $($res.Count) values, want one bool: $($res -join ' | ')" }
	if ($ok) { Write-Output "PASS: $Label" } else { Write-Output "FAIL: $Label"; $script:fails++ }
}

# --- parse case (every host) -------------------------------------------------
function Case-ParsesUnderWindowsPowerShellSyntax {
	if (-not (Test-Path -LiteralPath $InstallPs1 -PathType Leaf)) { Write-Host "  $InstallPs1 missing"; return $false }
	$tokens = $null
	$errors = $null
	[void][System.Management.Automation.Language.Parser]::ParseFile($InstallPs1, [ref]$tokens, [ref]$errors)
	$ok = $true
	foreach ($e in $errors) { Write-Host "  parse error: $($e.Extent.StartLineNumber): $($e.Message)"; $ok = $false }
	# pwsh 7 parses syntax that Windows PowerShell 5.1 rejects; refuse it here.
	$text = [System.IO.File]::ReadAllText($InstallPs1)
	foreach ($needle in @('??', '?.', '-Parallel')) {
		if ($text.Contains($needle)) { Write-Host "  contains PowerShell 7-only syntax: $needle"; $ok = $false }
	}
	foreach ($t in $tokens) {
		if (@('QuestionMark', 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket') -contains $t.Kind.ToString()) {
			Write-Host "  PowerShell 7-only operator '$($t.Text)' at line $($t.Extent.StartLineNumber)"
			$ok = $false
		}
	}
	return $ok
}

$labels = @(
	'bootstrap-installs-and-verifies',
	'already-at-version-skips-download',
	'latest-is-rejected',
	'tampered-checksum-refuses',
	'missing-sums-refuses',
	'disabled-with-no-binary-is-noop'
)

if (-not $onWindows) {
	foreach ($l in $labels) { Write-Output "SKIP: $l (Windows only)" }
	Check 'parses-under-windows-powershell-syntax' { Case-ParsesUnderWindowsPowerShellSyntax }
	if ($script:fails -ne 0) { Write-Output "$($script:fails) case(s) failed"; exit 1 }
	Write-Output 'ALL PASS (parse only; behavioural cases run on Windows)'
	exit 0
}

# --- staging (Windows) -------------------------------------------------------
if (-not $env:DIST) {
	Write-Output "FAIL: setup: set DIST to a directory holding the guardrail_* assets and SHA256SUMS (VERSION=$Version ./scripts/build-dist.sh)"
	exit 1
}
$Dist = $env:DIST
if (-not (Test-Path -LiteralPath (Join-Path $Dist 'SHA256SUMS') -PathType Leaf)) {
	Write-Output "FAIL: setup: $Dist\SHA256SUMS missing"
	exit 1
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('guardrail-ps1-harness-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$arch = 'amd64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
$asset = "guardrail_windows_$arch.exe"
$pwshExe = (Get-Process -Id $PID).Path
$n = 0
$out = ''
$err = ''
$rc = 0
$bootDest = ''

try {
	function Stage([string]$Root, [switch]$NoSums) {
		$d = Join-Path $Root $Version
		New-Item -ItemType Directory -Force -Path $d | Out-Null
		Copy-Item -Path (Join-Path $Dist 'guardrail_*') -Destination $d
		if (-not $NoSums) { Copy-Item -LiteralPath (Join-Path $Dist 'SHA256SUMS') -Destination $d }
	}
	Stage (Join-Path $tmp 'releases')
	Stage (Join-Path $tmp 'tampered')
	Stage (Join-Path $tmp 'nosums') -NoSums
	New-Item -ItemType Directory -Force -Path (Join-Path $tmp 'empty') | Out-Null

	# Flip the first hex digit of this platform's hash line.
	$sums = [System.IO.File]::ReadAllLines((Join-Path $Dist 'SHA256SUMS'))
	$tampered = foreach ($line in $sums) {
		if ($line.TrimEnd("`r").EndsWith(" $asset")) {
			$first = $line.Substring(0, 1)
			$flip = '0'
			if ($first -eq '0') { $flip = '1' }
			$flip + $line.Substring(1)
		} else { $line }
	}
	$tamperedSums = Join-Path (Join-Path (Join-Path $tmp 'tampered') $Version) 'SHA256SUMS'
	[System.IO.File]::WriteAllLines($tamperedSums, [string[]]$tampered)
	if ((Get-FileHash -LiteralPath $tamperedSums).Hash -eq (Get-FileHash -LiteralPath (Join-Path $Dist 'SHA256SUMS')).Hash) {
		Write-Output "FAIL: setup: could not tamper the $asset line of SHA256SUMS"
		exit 1
	}

	# Runs install.ps1 in-process inside a child pwsh, so the child can also
	# report its own PATH after the script returns.
	$runner = Join-Path $tmp 'runner.ps1'
	Set-Content -LiteralPath $runner -Encoding UTF8 -Value @'
param([string]$Target)
try { & $Target @args; $code = $LASTEXITCODE } catch { [Console]::Error.WriteLine("runner: $_"); $code = 1 }
[Console]::Out.WriteLine('install-harness-process-path=' + $env:Path)
exit $code
'@

	# --- helpers -------------------------------------------------------------
	function Run {
		$script:n++
		$o = Join-Path $tmp "out.$($script:n)"
		$e = Join-Path $tmp "err.$($script:n)"
		$ErrorActionPreference = 'Continue'
		& $pwshExe -NoProfile -ExecutionPolicy Bypass -File $runner $InstallPs1 @args 1> $o 2> $e
		$script:rc = $LASTEXITCODE
		$script:out = [System.IO.File]::ReadAllText($o)
		$script:err = [System.IO.File]::ReadAllText($e)
	}
	function Fresh {
		$d = Join-Path $tmp ('dest.' + [guid]::NewGuid().ToString('N').Substring(0, 8))
		New-Item -ItemType Directory -Force -Path $d | Out-Null
		return $d
	}
	function Dump { Write-Host "  stdout: $($script:out)"; Write-Host "  stderr: $($script:err)" }
	function WantRc([int]$Want) {
		if ($script:rc -ne $Want) { Write-Host "  exit $($script:rc), want $Want"; Dump; return $false }
		return $true
	}
	function Has([string]$Stream, [string]$Needle) {
		$text = $script:err
		if ($Stream -eq 'out') { $text = $script:out }
		if ($text.Contains($Needle)) { return $true }
		Write-Host "  $Stream lacks: $Needle"; Dump; return $false
	}
	function Reports([string]$Exe, [string]$Want) {
		$got = ''
		try {
			$ErrorActionPreference = 'Continue'
			$got = ((& $Exe version 2>$null) | Out-String).Trim()
		} catch { $got = '' }
		if ($got -ne "guardrail $Want") { Write-Host "  $Exe version printed '$got', want 'guardrail $Want'"; return $false }
		return $true
	}
	function Absent([string]$Path) {
		if (Test-Path -LiteralPath $Path) { Write-Host "  $Path exists"; return $false }
		return $true
	}
	function IsEmpty([string]$Dir) {
		$items = @(Get-ChildItem -LiteralPath $Dir -Force)
		if ($items.Count -ne 0) { Write-Host "  $Dir not empty: $($items.Name -join ', ')"; return $false }
		return $true
	}
	function PathHas([string]$List, [string]$Dir) {
		foreach ($p in ($List -split ';')) {
			if ($p.TrimEnd('\') -eq $Dir.TrimEnd('\')) { return $true }
		}
		return $false
	}

	# --- cases ---------------------------------------------------------------
	function Case-BootstrapInstallsAndVerifies {
		$envKey = Get-Item -LiteralPath 'HKCU:\Environment'
		$hadPath = $envKey.GetValueNames() -contains 'Path'
		$priorPath = $envKey.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
		$priorKind = 'ExpandString'
		if ($hadPath) { $priorKind = $envKey.GetValueKind('Path').ToString() }
		try {
			$script:bootDest = Fresh
			Run -Version $Version -Dest $script:bootDest -BaseUrl (Join-Path $tmp 'releases') -NoSetup
			if (-not (WantRc 0)) { return $false }
			if (-not (Reports (Join-Path $script:bootDest 'guardrail.exe') $Version)) { return $false }
			$m = [regex]::Match($script:out, '(?m)^install-harness-process-path=(.*?)\r?$')
			if (-not $m.Success -or -not (PathHas $m.Groups[1].Value $script:bootDest)) {
				Write-Host "  process PATH lacks $($script:bootDest)"; Dump; return $false
			}
			$userPath = (Get-Item -LiteralPath 'HKCU:\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
			if (-not (PathHas $userPath $script:bootDest)) {
				Write-Host "  User PATH lacks $($script:bootDest): $userPath"; return $false
			}
			return $true
		} finally {
			if ($hadPath) {
				New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -Value $priorPath -PropertyType $priorKind -Force | Out-Null
			} else {
				Remove-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -ErrorAction SilentlyContinue
			}
		}
	}

	function Case-AlreadyAtVersionSkipsDownload {
		if (-not $script:bootDest -or -not (Test-Path -LiteralPath (Join-Path $script:bootDest 'guardrail.exe'))) {
			Write-Host '  needs bootstrap-installs-and-verifies'; return $false
		}
		Run -Version $Version -Dest $script:bootDest -BaseUrl (Join-Path $tmp 'empty') -NoSetup
		if (-not (WantRc 0)) { return $false }
		if (-not (Has out 'already installed')) { return $false }
		return (Reports (Join-Path $script:bootDest 'guardrail.exe') $Version)
	}

	function Case-LatestIsRejected {
		$dest = Join-Path $tmp 'latest-dest'
		Run -Version latest -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup
		if (-not (WantRc 2)) { return $false }
		if (-not (Has err 'exact release tag')) { return $false }
		return (Absent $dest)
	}

	function Case-TamperedChecksumRefuses {
		$dest = Join-Path $tmp 'tampered-dest'
		Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'tampered') -NoSetup
		if (-not (WantRc 1)) { return $false }
		if (-not (Has err 'CHECKSUM MISMATCH')) { return $false }
		return (Absent (Join-Path $dest 'guardrail.exe'))
	}

	function Case-MissingSumsRefuses {
		$dest = Join-Path $tmp 'nosums-dest'
		Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'nosums') -NoSetup
		if (-not (WantRc 1)) { return $false }
		return (Absent $dest)
	}

	function Case-DisabledWithNoBinaryIsNoop {
		$dest = Fresh
		Run -Version $Version -State disabled -Dest $dest -BaseUrl (Join-Path $tmp 'empty') -NoSetup
		if (-not (WantRc 0)) { return $false }
		if (-not (Has out 'nothing to do')) { return $false }
		return (IsEmpty $dest)
	}

	Check 'bootstrap-installs-and-verifies' { Case-BootstrapInstallsAndVerifies }
	Check 'already-at-version-skips-download' { Case-AlreadyAtVersionSkipsDownload }
	Check 'latest-is-rejected' { Case-LatestIsRejected }
	Check 'tampered-checksum-refuses' { Case-TamperedChecksumRefuses }
	Check 'missing-sums-refuses' { Case-MissingSumsRefuses }
	Check 'disabled-with-no-binary-is-noop' { Case-DisabledWithNoBinaryIsNoop }
	Check 'parses-under-windows-powershell-syntax' { Case-ParsesUnderWindowsPowerShellSyntax }
} finally {
	Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:fails -ne 0) { Write-Output "$($script:fails) case(s) failed"; exit 1 }
Write-Output 'ALL PASS'
