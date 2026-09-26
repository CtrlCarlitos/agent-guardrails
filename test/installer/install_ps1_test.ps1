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
		if (@('QuestionMark', 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionDot', 'QuestionLBracket', 'AndAnd', 'OrOr') -contains $t.Kind.ToString()) {
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
	'disabled-with-no-binary-is-noop',
	'uninstall-removes-binary-and-plugin',
	'uninstall-keeps-path-when-dest-shared',
	'uninstall-purge-removes-state-roots',
	'uninstall-nothing-installed-is-ok',
	'purge-without-uninstall-exits-2',
	'state-with-uninstall-exits-2',
	'handoff-propagates-setup-exit-code',
	'noninteractive-disable-can-skip-setup',
	'update-verification-failure-exits-1-and-names-rollback',
	'update-refused-before-replacement-says-left-as-it-was'
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
	# RunNoConsole: Run, but with stdin piped instead of inherited, so no
	# `guardrail setup` it reaches can see a console.
	function RunNoConsole {
		$script:n++
		$o = Join-Path $tmp "out.$($script:n)"
		$e = Join-Path $tmp "err.$($script:n)"
		$ErrorActionPreference = 'Continue'
		'' | & $pwshExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner $InstallPs1 @args 1> $o 2> $e
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
	function Marker([string]$Dir) {
		New-Item -ItemType Directory -Force -Path $Dir | Out-Null
		Set-Content -LiteralPath (Join-Path $Dir 'marker') -Value 'marker'
	}
	function IsFile([string]$Path) {
		if (Test-Path -LiteralPath $Path -PathType Leaf) { return $true }
		Write-Host "  $Path missing"; return $false
	}

	# Save-UserPath / Restore-UserPath: install.ps1 writes the real User Path
	# in HKCU; every case that installs puts it back exactly as it was.
	function Save-UserPath {
		$envKey = Get-Item -LiteralPath 'HKCU:\Environment'
		$saved = @{ Had = ($envKey.GetValueNames() -contains 'Path'); Value = ''; Kind = 'ExpandString' }
		if ($saved.Had) {
			$saved.Value = $envKey.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
			$saved.Kind = $envKey.GetValueKind('Path').ToString()
		}
		return $saved
	}
	function Restore-UserPath($Saved) {
		if ($Saved.Had) {
			New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -Value $Saved.Value -PropertyType $Saved.Kind -Force | Out-Null
		} else {
			Remove-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -ErrorAction SilentlyContinue
		}
	}
	# Remove-HarnessExclusion: an elevated run makes install.ps1 add a Defender
	# exclusion for the harness's temp guardrail.exe; take it out again.
	function Remove-HarnessExclusion([string]$Exe) {
		try { Remove-MpPreference -ExclusionPath $Exe -ErrorAction SilentlyContinue } catch { $null = $_ }
	}

	# InSandbox <home> <block>: run <block> with USERPROFILE, LOCALAPPDATA and
	# APPDATA pointing into <home>, so no uninstall case touches real state.
	function InSandbox([string]$SandboxHome, [scriptblock]$Block) {
		$saved = @{ USERPROFILE = $env:USERPROFILE; LOCALAPPDATA = $env:LOCALAPPDATA; APPDATA = $env:APPDATA }
		try {
			$env:USERPROFILE = $SandboxHome
			$env:LOCALAPPDATA = Join-Path (Join-Path $SandboxHome 'AppData') 'Local'
			$env:APPDATA = Join-Path (Join-Path $SandboxHome 'AppData') 'Roaming'
			& $Block
		} finally {
			$env:USERPROFILE = $saved.USERPROFILE
			$env:LOCALAPPDATA = $saved.LOCALAPPDATA
			$env:APPDATA = $saved.APPDATA
		}
	}

	# --- cases ---------------------------------------------------------------
	function Case-BootstrapInstallsAndVerifies {
		$savedPath = Save-UserPath
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
			Restore-UserPath $savedPath
			if ($script:bootDest) { Remove-HarnessExclusion (Join-Path $script:bootDest 'guardrail.exe') }
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

	function Case-NoSetupPrintsTheNextSteps {
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		try {
			# A detected plane that is not registered yet: the steps have something to say.
			$claudeDir = Join-Path $sbHome '.claude'
			New-Item -ItemType Directory -Force -Path $claudeDir | Out-Null
			Set-Content -LiteralPath (Join-Path $claudeDir 'settings.json') -Value '{}'
			InSandbox $sbHome { Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup }
			if (-not (WantRc 0)) { return $false }
			if (-not (Has out 'setup skipped')) { return $false }
			if (-not (Has out 'next steps:')) { return $false }
			return (Has out 'claude: not registered')
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion (Join-Path $dest 'guardrail.exe')
		}
	}

	function Case-UninstallRemovesBinaryAndPlugin {
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		$exe = Join-Path $dest 'guardrail.exe'
		try {
			Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup
			if (-not (WantRc 0)) { return $false }
			$pluginDir = Join-Path (Join-Path (Join-Path $sbHome '.local') 'share') 'guardrail'
			New-Item -ItemType Directory -Force -Path $pluginDir | Out-Null
			Set-Content -LiteralPath (Join-Path $pluginDir 'guardrail.js') -Value '// fake plugin'
			$stateDir = Join-Path (Join-Path (Join-Path $sbHome 'AppData') 'Local') 'guardrail'
			Marker $stateDir
			InSandbox $sbHome { Run -Uninstall -Dest $dest -NoSetup }
			if (-not (WantRc 0)) { return $false }
			if (-not (Has out "install: guardrail removed from $dest")) { return $false }
			if (-not (Absent $exe)) { return $false }
			if (-not (Absent (Join-Path $pluginDir 'guardrail.js'))) { return $false }
			if (-not (IsFile (Join-Path $stateDir 'marker'))) { return $false }
			$userPath = (Get-Item -LiteralPath 'HKCU:\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
			if (PathHas $userPath $dest) { Write-Host "  User PATH still has $($dest): $userPath"; return $false }
			# dest held only guardrail, so it goes with its PATH entry
			return (Absent $dest)
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion $exe
		}
	}

	function Case-UninstallKeepsPathWhenDestShared {
		# %USERPROFILE%\.local\bin is shared (Claude Code, uv, pipx): the PATH
		# entry is not the installer's to remove while other tools live there.
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		$exe = Join-Path $dest 'guardrail.exe'
		$foreign = Join-Path $dest 'other-tool.exe'
		try {
			Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup
			if (-not (WantRc 0)) { return $false }
			Set-Content -LiteralPath $foreign -Value 'not guardrail'
			InSandbox $sbHome { Run -Uninstall -Dest $dest -NoSetup }
			if (-not (WantRc 0)) { return $false }
			if (-not (Has out "install: leaving $dest on PATH (other tools live there)")) { return $false }
			if (-not (Absent $exe)) { return $false }
			if (-not (IsFile $foreign)) { return $false }
			$userPath = (Get-Item -LiteralPath 'HKCU:\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
			if (-not (PathHas $userPath $dest)) { Write-Host "  User PATH lost $($dest): $userPath"; return $false }
			return $true
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion $exe
		}
	}

	function Case-UninstallSweepsOldOnlyDest {
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		$exe = Join-Path $dest 'guardrail.exe'
		$old = "$exe.old"
		try {
			Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup
			if (-not (WantRc 0)) { return $false }
			Move-Item -LiteralPath $exe -Destination $old
			InSandbox $sbHome { Run -Uninstall -Dest $dest -NoSetup }
			if (-not (WantRc 0)) { return $false }
			if (-not (Has out "install: nothing installed at $dest")) { return $false }
			if (-not (Absent $old)) { return $false }
			$userPath = (Get-Item -LiteralPath 'HKCU:\Environment').GetValue('Path', '', 'DoNotExpandEnvironmentNames')
			if (PathHas $userPath $dest) { Write-Host "  User PATH still has $($dest): $userPath"; return $false }
			return (Absent $dest)
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion $exe
		}
	}

	function Case-UninstallPurgeRemovesStateRoots {
		$dest = Fresh
		$sbHome = Fresh
		$roots = @(
			(Join-Path (Join-Path (Join-Path $sbHome 'AppData') 'Local') 'guardrail'),
			(Join-Path (Join-Path (Join-Path $sbHome 'AppData') 'Roaming') 'guardrail'),
			(Join-Path (Join-Path (Join-Path $sbHome '.local') 'state') 'guardrail'),
			(Join-Path (Join-Path (Join-Path $sbHome '.local') 'share') 'guardrail')
		)
		foreach ($r in $roots) { Marker $r }
		InSandbox $sbHome { Run -Uninstall -Purge -Dest $dest -NoSetup }
		if (-not (WantRc 0)) { return $false }
		foreach ($r in $roots) {
			if (-not (Absent $r)) { return $false }
			if (-not (Has out "install: removed $r")) { return $false }
		}
		# only the guardrail roots, never their parents
		if (-not (Test-Path -LiteralPath (Join-Path (Join-Path $sbHome '.local') 'share') -PathType Container)) {
			Write-Host '  a parent of a guardrail root was removed'; return $false
		}
		return $true
	}

	function Case-UninstallNothingInstalledIsOk {
		$dest = Fresh
		$sbHome = Fresh
		InSandbox $sbHome { Run -Uninstall -Dest $dest -NoSetup }
		if (-not (WantRc 0)) { return $false }
		if (-not (Has out "nothing installed at $dest")) { return $false }
		return (IsEmpty $dest)
	}

	function Case-HandoffPropagatesSetupExitCode {
		# The real binary's `setup --state disabled`, with stdin piped rather
		# than a console, refuses with exit 3 (operator action pending, #364;
		# it was 2 before); the script must exit with setup's code, not its
		# own, so a caller can tell this apart from its own usage exit 2.
		# Disable is the probe because a bare
		# `setup` on a machine with no enrolled operator now arms the planes
		# and exits 0 (ADR-0030). Sandboxed roots and a piped stdin keep it
		# off real state. The binary is placed first with -NoSetup so the
		# disable run finds one and hands off.
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		$exe = Join-Path $dest 'guardrail.exe'
		try {
			InSandbox $sbHome { Run -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup }
			if (-not (WantRc 0)) { return $false }
			InSandbox $sbHome { RunNoConsole -Version $Version -State disabled -Dest $dest -BaseUrl (Join-Path $tmp 'releases') }
			if (-not (WantRc 3)) { return $false }
			if (-not (Has err 'requires an interactive local terminal')) { return $false }
			if (-not (Has err 'operator action pending')) { return $false }
			return (Reports $exe $Version)
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion $exe
		}
	}

	# UpdateFailure: dot-source install.ps1 in a child pwsh, point it at a fake
	# guardrail.cmd whose `update` exits 1, and run Update-Installed (the real
	# self-update path cannot be staged here: the built binary is not at the
	# self-update floor). $Replaced picks whether the fake reports the new
	# version afterwards, i.e. whether the swap happened before the failure.
	function UpdateFailure([bool]$Replaced) {
		$dest = Fresh
		$reported = 'v0.19.2-dev'
		if ($Replaced) { $reported = $Version }
		[System.IO.File]::WriteAllText((Join-Path $dest 'guardrail.cmd'), "@echo off`r`nif ""%~1""==""version"" echo guardrail $reported& exit /b 0`r`nexit /b 1`r`n")
		$child = Join-Path $dest 'child.ps1'
		Set-Content -LiteralPath $child -Encoding UTF8 -Value @"
. '$InstallPs1'
`$Version = '$Version'
`$script:Exe = '$(Join-Path $dest 'guardrail.cmd')'
`$script:Installed = 'v0.19.2-dev'
Update-Installed
exit 0
"@
		$o = Join-Path $tmp "uf-out.$Replaced"
		$e = Join-Path $tmp "uf-err.$Replaced"
		$ErrorActionPreference = 'Continue'
		& $pwshExe -NoProfile -ExecutionPolicy Bypass -File $child 1> $o 2> $e
		$script:rc = $LASTEXITCODE
		$script:out = [System.IO.File]::ReadAllText($o)
		# Windows PowerShell 5.1 wraps redirected native stderr at the console
		# width, splitting words; rejoin before matching.
		$script:err = [System.IO.File]::ReadAllText($e) -replace "[\r\n]+", ''
	}

	function Case-UpdateVerificationFailureExits1AndNamesRollback {
		UpdateFailure $true
		if (-not (WantRc 1)) { return $false }
		if (-not (Has err 'already replaced')) { return $false }
		return (Has err 'guardrail.cmd update v0.19.2-dev')
	}

	function Case-UpdateRefusedBeforeReplacementSaysLeftAsItWas {
		UpdateFailure $false
		if (-not (WantRc 1)) { return $false }
		return (Has err 'left as it was')
	}

	function Case-NoninteractiveDisableCanSkipSetup {
		# An unattended caller can opt into installing the binary while leaving
		# the plane state unchanged instead of turning the terminal refusal into
		# a failed run. The ordinary path above must keep propagating exit 2.
		$savedPath = Save-UserPath
		$dest = Fresh
		$sbHome = Fresh
		$exe = Join-Path $dest 'guardrail.exe'
		try {
			InSandbox $sbHome { RunNoConsole -Version $Version -State disabled -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -SetupIfInteractive }
			if (-not (WantRc 0)) { return $false }
			if (-not (Has out 'setup --state disabled skipped (no interactive local terminal)')) { return $false }
			if (-not (Has out 'run guardrail setup --state disabled from an interactive shell')) { return $false }
			return (Reports $exe $Version)
		} finally {
			Restore-UserPath $savedPath
			Remove-HarnessExclusion $exe
		}
	}

	function Case-PurgeWithoutUninstallExits2 {
		$dest = Fresh
		$sbHome = Fresh
		$stateDir = Join-Path (Join-Path (Join-Path $sbHome 'AppData') 'Local') 'guardrail'
		Marker $stateDir
		InSandbox $sbHome { Run -Purge -Version $Version -Dest $dest -BaseUrl (Join-Path $tmp 'releases') -NoSetup }
		if (-not (WantRc 2)) { return $false }
		if (-not (Has err '-Purge only works with -Uninstall')) { return $false }
		if (-not (IsEmpty $dest)) { return $false }
		return (IsFile (Join-Path $stateDir 'marker'))
	}

	function Case-StateWithUninstallExits2 {
		$dest = Fresh
		$sbHome = Fresh
		InSandbox $sbHome { Run -Uninstall -State disabled -Dest $dest -NoSetup }
		if (-not (WantRc 2)) { return $false }
		if (-not (Has err '-State cannot be combined with -Uninstall')) { return $false }
		return (IsEmpty $dest)
	}

	Check 'bootstrap-installs-and-verifies' { Case-BootstrapInstallsAndVerifies }
	Check 'already-at-version-skips-download' { Case-AlreadyAtVersionSkipsDownload }
	Check 'latest-is-rejected' { Case-LatestIsRejected }
	Check 'tampered-checksum-refuses' { Case-TamperedChecksumRefuses }
	Check 'missing-sums-refuses' { Case-MissingSumsRefuses }
	Check 'disabled-with-no-binary-is-noop' { Case-DisabledWithNoBinaryIsNoop }
	Check 'no-setup-prints-the-next-steps' { Case-NoSetupPrintsTheNextSteps }
	Check 'uninstall-removes-binary-and-plugin' { Case-UninstallRemovesBinaryAndPlugin }
	Check 'uninstall-keeps-path-when-dest-shared' { Case-UninstallKeepsPathWhenDestShared }
	Check 'uninstall-sweeps-old-only-dest' { Case-UninstallSweepsOldOnlyDest }
	Check 'uninstall-purge-removes-state-roots' { Case-UninstallPurgeRemovesStateRoots }
	Check 'uninstall-nothing-installed-is-ok' { Case-UninstallNothingInstalledIsOk }
	Check 'purge-without-uninstall-exits-2' { Case-PurgeWithoutUninstallExits2 }
	Check 'state-with-uninstall-exits-2' { Case-StateWithUninstallExits2 }
	Check 'handoff-propagates-setup-exit-code' { Case-HandoffPropagatesSetupExitCode }
	Check 'noninteractive-disable-can-skip-setup' { Case-NoninteractiveDisableCanSkipSetup }
	Check 'update-verification-failure-exits-1-and-names-rollback' { Case-UpdateVerificationFailureExits1AndNamesRollback }
	Check 'update-refused-before-replacement-says-left-as-it-was' { Case-UpdateRefusedBeforeReplacementSaysLeftAsItWas }
	Check 'parses-under-windows-powershell-syntax' { Case-ParsesUnderWindowsPowerShellSyntax }
} finally {
	Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:fails -ne 0) { Write-Output "$($script:fails) case(s) failed"; exit 1 }
Write-Output 'ALL PASS'
