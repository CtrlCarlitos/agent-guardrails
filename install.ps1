# install.ps1: install an exact, checksum-verified guardrail release, then
# hand off to `guardrail setup`. Windows PowerShell 5.1 and PowerShell 7.
#
#   install.ps1 -Version <tag> [-State enabled|disabled] [-Dest <dir>]
#               [-BaseUrl <url-or-dir>] [-NoSetup] [-SetupIfInteractive]
#   install.ps1 -Uninstall [-Purge] [-Dest <dir>] [-NoSetup]
#   install.ps1 -Help
#
# Exit codes: 2 usage / unsupported platform; 1 download, checksum, install
# or post-install version failure, or an uninstall that could not disable
# the planes or remove a file; otherwise the exit code of `guardrail setup`
# (0 with -NoSetup, and after an uninstall; a first install with no enrolled
# operator arms the planes and exits 0; 3 when the change needs the operator:
# no authenticator enrolled, no interactive terminal for an enrolled operator,
# the approval daemon not running, or the request denied or expired. The binary
# is installed and the planes keep what is registered; a caller may treat 3 as
# a warning).
# PowerShell itself rejects unknown or malformed parameters (exit 1 when run
# with -File).
#
# Dot-sourcing (`. .\install.ps1`) only defines the helper functions; the
# test harness uses that to exercise them without installing anything.
[CmdletBinding(PositionalBinding = $false)]
param(
	[string]$Version,
	[ValidateSet('enabled', 'disabled')][string]$State = 'enabled',
	[string]$Dest,
	[string]$BaseUrl,
	[switch]$NoSetup,
	[switch]$SetupIfInteractive,
	[switch]$Uninstall,
	[switch]$Purge,
	[switch]$Help
)

$ErrorActionPreference = 'Stop'
# -State has a default, so only $PSBoundParameters says whether it was passed.
$script:StateGiven = $PSBoundParameters.ContainsKey('State')

# Oldest release whose `guardrail update` is the sanctioned replacement path.
# A fixed historical constant, not a pin.
$SelfUpdateFloor = 'v0.19.2-dev'
$DefaultBaseUrl = 'https://github.com/CtrlCarlitos/agent-guardrails/releases/download'

$script:Asset = ''
$script:Exe = ''
$script:Installed = ''
$script:Tmp = ''
$script:BaseIsHttp = $false
$script:DisableCode = 1

function Say([string]$Message) { Write-Host "install: $Message" }

function Cleanup {
	if ($script:Tmp) {
		Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
		$script:Tmp = ''
	}
}

# Die <exit-code> <message>
function Die([int]$Code, [string]$Message) {
	[Console]::Error.WriteLine("install: $Message")
	Cleanup
	exit $Code
}

function Show-Usage {
	Write-Host @'
Usage:
  install.ps1 -Version <tag> [-State enabled|disabled] [-Dest <dir>]
              [-BaseUrl <url-or-dir>] [-NoSetup] [-SetupIfInteractive]
  install.ps1 -Uninstall [-Purge] [-Dest <dir>] [-NoSetup]
  install.ps1 -Help

  -Version <tag>     Exact release tag, e.g. v0.23.0-dev (required; 'latest' is not supported).
  -State <state>     enabled (default) or disabled.
  -Dest <dir>        Install directory (default: $env:USERPROFILE\.local\bin).
  -BaseUrl <base>    Release base: http(s) URL, file://<dir> or a directory
                     laid out as <base>\<tag>\<asset>
                     (default: https://github.com/CtrlCarlitos/agent-guardrails/releases/download).
  -NoSetup           Stop once the binary is installed and verified; do not run `guardrail setup`.
                     With -Uninstall: do not run `guardrail setup --state disabled` first.
  -SetupIfInteractive
                     With -State disabled, install or update the binary but skip setup and exit 0
                     when stdin is not an interactive console. Prints the command needed to finish.
  -Uninstall         Disable every plane (`guardrail setup --state disabled`), then remove
                     guardrail.exe, the plugin file guardrail.js, the user PATH entry and
                     the Defender exclusion.
  -Purge             With -Uninstall: also remove guardrail's state, config and data directories.
'@
}

# --- pure helpers -------------------------------------------------------------

# Test-ValidVersion <string>: exact release tag, nothing else. \z, not $, so a
# trailing newline is refused; -cmatch, so 'V1.2.3' is refused.
function Test-ValidVersion([string]$Tag) {
	return ($Tag -cmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\z')
}

# Compare-DecimalString <a> <b>: -1/0/1 for two strings of ASCII digits, of any
# length (no integer overflow).
function Compare-DecimalString([string]$A, [string]$B) {
	$a1 = $A.TrimStart('0')
	$b1 = $B.TrimStart('0')
	if ($a1.Length -ne $b1.Length) {
		if ($a1.Length -gt $b1.Length) { return 1 }
		return -1
	}
	$c = [string]::CompareOrdinal($a1, $b1)
	if ($c -gt 0) { return 1 }
	if ($c -lt 0) { return -1 }
	return 0
}

# Test-VersionAtLeast <a> <b>: a >= b on MAJOR.MINOR.PATCH; any -suffix is
# ignored. Both arguments must already satisfy Test-ValidVersion.
function Test-VersionAtLeast([string]$A, [string]$B) {
	$af = $A.Substring(1).Split('-')[0].Split('.')
	$bf = $B.Substring(1).Split('-')[0].Split('.')
	for ($i = 0; $i -lt 3; $i++) {
		$c = Compare-DecimalString $af[$i] $bf[$i]
		if ($c -gt 0) { return $true }
		if ($c -lt 0) { return $false }
	}
	return $true
}

# Get-SumsHash <lines> <asset>: the SHA-256 on the SHA256SUMS line anchored on
# ` <asset>` at end of line (a trailing CR tolerated), or '' when there is none.
function Get-SumsHash([string[]]$Lines, [string]$AssetName) {
	$pattern = '^([0-9A-Fa-f]{64}) [ *]?' + [regex]::Escape($AssetName) + '\r?\z'
	foreach ($line in $Lines) {
		$m = [regex]::Match($line, $pattern)
		if ($m.Success) { return $m.Groups[1].Value }
	}
	return ''
}

# Test-PathListHas <list> <dir>: a ';'-separated PATH already has an entry
# equal to <dir>, ignoring a trailing backslash on either side.
function Test-PathListHas([string]$List, [string]$Dir) {
	$want = $Dir.TrimEnd('\')
	foreach ($entry in ($List -split ';')) {
		if ($entry -and ($entry.TrimEnd('\') -eq $want)) { return $true }
	}
	return $false
}

# Remove-PathListEntry <list> <dir>: the ';'-separated PATH without the
# entries equal to <dir> (ignoring a trailing backslash on either side); every
# other entry, empty ones included, is kept byte for byte.
function Remove-PathListEntry([string]$List, [string]$Dir) {
	$want = $Dir.TrimEnd('\')
	$kept = @()
	foreach ($entry in ($List -split ';')) {
		if ($entry -and ($entry.TrimEnd('\') -eq $want)) { continue }
		$kept += $entry
	}
	return ($kept -join ';')
}

# Get-PluginDir <userprofile>: where `guardrail setup` writes guardrail.js
# (the binary's planePluginDir), or '' when USERPROFILE is unset.
function Get-PluginDir([string]$UserProfile) {
	if (-not $UserProfile) { return '' }
	return (Join-Path (Join-Path (Join-Path $UserProfile '.local') 'share') 'guardrail')
}

# Get-PurgeDirs <userprofile> <localappdata> <appdata>: every directory
# guardrail keeps state, config or data in; roots whose variable is unset are
# left out.
function Get-PurgeDirs([string]$UserProfile, [string]$LocalAppData, [string]$AppData) {
	$dirs = @()
	if ($LocalAppData) { $dirs += (Join-Path $LocalAppData 'guardrail') }
	if ($AppData) { $dirs += (Join-Path $AppData 'guardrail') }
	if ($UserProfile) {
		$dirs += (Join-Path (Join-Path (Join-Path $UserProfile '.local') 'state') 'guardrail')
		$dirs += (Get-PluginDir $UserProfile)
	}
	return $dirs
}

# Invoke-WithRetry <action>: run <action> up to three times, waiting 250, then
# 500 ms between attempts, and rethrow the last failure. A scanner or indexer
# can briefly hold a freshly written or just-exited binary (the #205 flake
# class `guardrail update` retries the same way).
function Invoke-WithRetry([scriptblock]$Action) {
	for ($attempt = 1; $attempt -le 3; $attempt++) {
		try {
			& $Action
			return
		} catch {
			if ($attempt -eq 3) { throw }
			Start-Sleep -Milliseconds (250 * $attempt)
		}
	}
}

# --- steps --------------------------------------------------------------------

function Resolve-Arguments {
	if ($Help) {
		Show-Usage
		exit 0
	}
	if ($Purge -and -not $Uninstall) { Die 2 '-Purge only works with -Uninstall' }
	if ($SetupIfInteractive -and $Uninstall) { Die 2 '-SetupIfInteractive cannot be combined with -Uninstall' }
	if ($SetupIfInteractive -and $NoSetup) { Die 2 '-SetupIfInteractive cannot be combined with -NoSetup' }
	if ($SetupIfInteractive -and $State -ne 'disabled') { Die 2 '-SetupIfInteractive requires -State disabled' }
	if ($script:StateGiven -and $Uninstall) { Die 2 '-State cannot be combined with -Uninstall' }
	# -Uninstall needs no release; a -Version given anyway must still be valid.
	if (-not $Version -and -not $Uninstall) {
		Die 2 "-Version is required: pass an exact release tag such as v0.23.0-dev ('latest' is not supported)"
	}
	if ($Version -and -not (Test-ValidVersion $Version)) {
		Die 2 "-Version must be an exact release tag such as v0.23.0-dev, got '$Version' ('latest' is not supported)"
	}

	if (-not $Dest) {
		if (-not $env:USERPROFILE) { Die 2 'USERPROFILE is not set; pass -Dest <dir>' }
		$script:Dest = Join-Path (Join-Path $env:USERPROFILE '.local') 'bin'
	}
	# The plugin file and two of the state roots live under USERPROFILE.
	if ($Uninstall -and -not $env:USERPROFILE) {
		Die 2 'USERPROFILE is not set; -Uninstall needs it to find the plugin and state directories'
	}
	# Absolute, so the PATH entry and the Defender exclusion name a real place.
	$script:Dest = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:Dest).TrimEnd('\')
	$script:Exe = Join-Path $script:Dest 'guardrail.exe'

	if (-not $BaseUrl) { $script:BaseUrl = $DefaultBaseUrl }
	if ($script:BaseUrl -match '^https?://') {
		$script:BaseIsHttp = $true
		$script:BaseUrl = $script:BaseUrl.TrimEnd('/')
	} elseif ($script:BaseUrl -match '^file://') {
		$local = ''
		try { $local = ([Uri]$script:BaseUrl).LocalPath } catch { $local = '' }
		if (-not $local -or -not (Test-Path -LiteralPath $local -PathType Container)) {
			Die 2 "-BaseUrl $($script:BaseUrl) is not a directory"
		}
		$script:BaseUrl = $local.TrimEnd('/', '\')
	} else {
		if (-not (Test-Path -LiteralPath $script:BaseUrl -PathType Container)) {
			Die 2 "-BaseUrl must be an http(s):// URL, a file:// URL or an existing directory, got '$($script:BaseUrl)'"
		}
		$script:BaseUrl = $script:BaseUrl.TrimEnd('/', '\')
	}
}

function Resolve-Platform {
	# $IsWindows exists only in PowerShell 6+; Windows PowerShell 5.1 is Windows.
	if ((Test-Path Variable:IsWindows) -and -not $IsWindows) {
		Die 2 'unsupported platform; install.ps1 is for Windows (use install.sh on Linux and macOS)'
	}
	$arch = 'amd64'
	if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
	$script:Asset = "guardrail_windows_$arch.exe"
}

# Get-GuardrailVersionLine: the first line `guardrail version` prints, or ''
# when the binary cannot run. A native-command boundary: under 'Stop', stderr
# from a native command is a terminating error in Windows PowerShell 5.1.
function Get-GuardrailVersionLine {
	$line = ''
	try {
		$ErrorActionPreference = 'Continue'
		$PSNativeCommandUseErrorActionPreference = $false
		$lines = @(& $script:Exe version 2>$null)
		if ($LASTEXITCODE -eq 0 -and $lines.Count -gt 0) { $line = ([string]$lines[0]).Trim() }
	} catch {
		$line = ''
	}
	return $line
}

# Get-InstalledVersion: sets $script:Installed to the installed binary's
# version tag, or to '' when there is no usable binary at <dest>\guardrail.exe.
function Get-InstalledVersion {
	$script:Installed = ''
	if (-not (Test-Path -LiteralPath $script:Exe -PathType Leaf)) { return }
	$reported = Get-GuardrailVersionLine
	if ($reported.StartsWith('guardrail ')) { $script:Installed = $reported.Substring(10) }
	if (-not (Test-ValidVersion $script:Installed)) { $script:Installed = '' }
}

# Get-ReleaseFile <file>: copy <base>/<version>/<file> into the temp dir.
function Get-ReleaseFile([string]$File) {
	$target = Join-Path $script:Tmp $File
	if ($script:BaseIsHttp) {
		$src = "$($script:BaseUrl)/$Version/$File"
	} else {
		$src = Join-Path (Join-Path $script:BaseUrl $Version) $File
	}
	try {
		if ($script:BaseIsHttp) {
			# Windows PowerShell 5.1 may default to TLS 1.0/1.1, which GitHub refuses.
			[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
			$ProgressPreference = 'SilentlyContinue'
			Invoke-WebRequest -UseBasicParsing -Uri $src -OutFile $target -TimeoutSec 180
		} else {
			Copy-Item -LiteralPath $src -Destination $target
		}
	} catch {
		Die 1 "download failed: $src"
	}
}

# Confirm-Checksum: the downloaded asset matches its line in the release's
# SHA256SUMS.
function Confirm-Checksum {
	$lines = @()
	try { $lines = [System.IO.File]::ReadAllLines((Join-Path $script:Tmp 'SHA256SUMS')) } catch { $lines = @() }
	$want = Get-SumsHash $lines $script:Asset
	if (-not $want) {
		Die 1 "CHECKSUM MISMATCH: SHA256SUMS for $Version has no entry for $($script:Asset); nothing installed"
	}
	$got = ''
	try { $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $script:Tmp $script:Asset)).Hash } catch { $got = '' }
	if (-not [string]::Equals($got, $want, [StringComparison]::OrdinalIgnoreCase)) {
		Die 1 "CHECKSUM MISMATCH: $($script:Asset) does not match SHA256SUMS for $Version; nothing installed"
	}
}

# Add-ToPath: append <dest> to the User Path (unless an entry already equals
# it) and to this process's PATH. The User value is read and written raw, as
# REG_EXPAND_SZ, so entries like %USERPROFILE%\bin survive unexpanded.
function Add-ToPath {
	$processPath = [string]$env:Path
	if (-not (Test-PathListHas $processPath $script:Dest)) {
		$env:Path = ($processPath.TrimEnd(';') + ';' + $script:Dest).TrimStart(';')
	}
	try {
		$key = Get-Item -LiteralPath 'HKCU:\Environment'
		$userPath = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
		if (Test-PathListHas $userPath $script:Dest) { return }
		$newPath = ($userPath.TrimEnd(';') + ';' + $script:Dest).TrimStart(';')
		New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -Value $newPath -PropertyType ExpandString -Force | Out-Null
		# Setting any User variable broadcasts WM_SETTINGCHANGE, so new
		# terminals pick up the Path written above.
		[Environment]::SetEnvironmentVariable('GUARDRAIL_INSTALL_PATH_NOTIFY', '1', 'User')
		[Environment]::SetEnvironmentVariable('GUARDRAIL_INSTALL_PATH_NOTIFY', $null, 'User')
		Say "added $($script:Dest) to your user PATH (open a new terminal to use it)"
	} catch {
		[Console]::Error.WriteLine("install: warning: could not add $($script:Dest) to your user PATH; add it yourself")
	}
}

function Install-Bootstrap {
	try {
		$script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('guardrail-install-' + [guid]::NewGuid().ToString('N'))
		New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null
	} catch {
		$script:Tmp = ''
		Die 1 'cannot create a temporary directory'
	}

	Say "downloading $($script:Asset) $Version from $($script:BaseUrl)"
	Get-ReleaseFile $script:Asset
	Get-ReleaseFile 'SHA256SUMS'
	Confirm-Checksum

	try {
		New-Item -ItemType Directory -Force -Path $script:Dest | Out-Null
	} catch {
		Die 1 "cannot create $($script:Dest)"
	}
	# Stage beside the target, unblock, then rename, so a failed step never
	# leaves a partial or still-blocked guardrail.exe.
	$staged = Join-Path $script:Dest '.guardrail.install.exe'
	try {
		Copy-Item -LiteralPath (Join-Path $script:Tmp $script:Asset) -Destination $staged -Force
		Unblock-File -LiteralPath $staged
	} catch {
		Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
		Die 1 "failed to install $($script:Exe)"
	}
	try {
		Invoke-WithRetry { Move-Item -LiteralPath $staged -Destination $script:Exe -Force }
	} catch {
		Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
		Die 1 "failed to install $($script:Exe): it may be in use (a running guardrail, such as the approval daemon, which exits after 10 idle minutes); stop it or reboot, then re-run"
	}
	Cleanup
	Add-ToPath
}

function Update-Installed {
	Say "updating $($script:Exe) from $($script:Installed) to $Version via guardrail update"
	$code = 1
	try {
		$ErrorActionPreference = 'Continue'
		$PSNativeCommandUseErrorActionPreference = $false
		& $script:Exe update $Version
		$code = $LASTEXITCODE
	} catch {
		$code = 1
	}
	if ($code -ne 0) { Die 1 "guardrail update $Version failed; $($script:Exe) left as it was" }
}

function Confirm-Installed {
	$got = Get-GuardrailVersionLine
	if ($got -cne "guardrail $Version") {
		Die 1 "$($script:Exe) did not report guardrail $Version (got '$got')"
	}
}

# Add-DefenderExclusion: exclude exactly <dest>\guardrail.exe (never a
# directory or a process name). Needs an elevated shell; otherwise print the
# command and carry on.
function Add-DefenderExclusion {
	try {
		$pref = Get-MpPreference
		if (@($pref.ExclusionPath) -contains $script:Exe) { return }
		Add-MpPreference -ExclusionPath $script:Exe
		Say "added a Microsoft Defender exclusion for $($script:Exe)"
	} catch {
		[Console]::Error.WriteLine('install: warning: could not add the Defender exclusion (needs an elevated shell); run:')
		[Console]::Error.WriteLine("Add-MpPreference -ExclusionPath `"$($script:Exe)`"")
	}
}

# Remove-FromPath: drop the User Path entry equal to <dest>, leaving every
# other entry, and the value's kind, as they were. Only called once <dest> is
# empty: %USERPROFILE%\.local\bin is shared with other tools (Claude Code, uv,
# pipx), so the entry may not be ours to remove.
function Remove-FromPath {
	try {
		$key = Get-Item -LiteralPath 'HKCU:\Environment'
		if (-not ($key.GetValueNames() -contains 'Path')) { return }
		$userPath = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
		if (-not (Test-PathListHas $userPath $script:Dest)) { return }
		$kind = $key.GetValueKind('Path').ToString()
		$newPath = Remove-PathListEntry $userPath $script:Dest
		New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name 'Path' -Value $newPath -PropertyType $kind -Force | Out-Null
		# Broadcast WM_SETTINGCHANGE, as Add-ToPath does.
		[Environment]::SetEnvironmentVariable('GUARDRAIL_INSTALL_PATH_NOTIFY', '1', 'User')
		[Environment]::SetEnvironmentVariable('GUARDRAIL_INSTALL_PATH_NOTIFY', $null, 'User')
		Say "removed $($script:Dest) from your user PATH"
	} catch {
		[Console]::Error.WriteLine("install: warning: could not remove $($script:Dest) from your user PATH; remove it yourself")
	}
}

# Remove-DefenderExclusion: undo Add-DefenderExclusion. Needs an elevated
# shell; otherwise print the command and carry on.
function Remove-DefenderExclusion {
	try {
		Remove-MpPreference -ExclusionPath $script:Exe
	} catch {
		[Console]::Error.WriteLine('install: warning: could not remove the Defender exclusion (needs an elevated shell); if one exists, run:')
		[Console]::Error.WriteLine("Remove-MpPreference -ExclusionPath `"$($script:Exe)`"")
	}
}

# Remove-StateRoots: -Purge; remove every directory guardrail keeps state,
# config or data in.
function Remove-StateRoots {
	foreach ($root in (Get-PurgeDirs $env:USERPROFILE $env:LOCALAPPDATA $env:APPDATA)) {
		if (-not (Test-Path -LiteralPath $root)) { continue }
		try {
			Remove-Item -LiteralPath $root -Recurse -Force
		} catch {
			Die 1 "cannot remove $root"
		}
		Say "removed $root"
	}
}

# Test-SetupSupported: whether <dest>\guardrail.exe has the `setup`
# subcommand. Probed as `setup --state disabled` with stdin piped, not the
# console: disabling always needs a terminal, so a binary that has `setup`
# refuses before touching anything (exit 3 from #364 on, 2 before it, with
# "requires an interactive local terminal"), while one that predates it exits 2
# with "unknown subcommand"; only that pair reads as unsupported.
# A bare `setup` would not do: with no operator enrolled it arms the planes
# (ADR-0030), and a probe must never have side effects. Probing first keeps
# the real run's output streaming to the console.
function Test-SetupSupported {
	$text = ''
	$code = 0
	try {
		$ErrorActionPreference = 'Continue'
		$PSNativeCommandUseErrorActionPreference = $false
		$text = (@('' | & $script:Exe setup --state disabled 2>&1) | ForEach-Object { [string]$_ }) -join "`n"
		$code = $LASTEXITCODE
	} catch {
		return $true
	}
	return -not (($code -eq 2) -and $text.Contains('unknown subcommand'))
}

# Test-InteractiveInput: whether a child process inherits terminal stdin.
# If the host cannot answer, treat it as non-interactive: this opt-in path
# only skips a state change and must never guess that approval is possible.
function Test-InteractiveInput {
	try { return -not [Console]::IsInputRedirected } catch { return $false }
}

$OldBinaryHint = "this guardrail predates 'setup'; re-run the installer with -Version <a release that has it>"

# Invoke-DisablePlanes: run `guardrail setup --state disabled` (or, on a
# binary that predates setup, `guardrail plane disable --all`) and leave its
# exit code in $script:DisableCode. Its own function so the relaxed error
# preference a native call needs stays out of the removals that follow; the
# code goes through a variable, not the output stream, so setup's own output
# is never captured.
function Invoke-DisablePlanes {
	$script:DisableCode = 1
	$disableArgs = @('setup', '--state', 'disabled')
	if (-not (Test-SetupSupported)) {
		Say "this guardrail predates 'setup'; running guardrail plane disable --all"
		$disableArgs = @('plane', 'disable', '--all')
	}
	# Called bare, not piped: setup needs the console as its stdin and stdout.
	try {
		$ErrorActionPreference = 'Continue'
		$PSNativeCommandUseErrorActionPreference = $false
		& $script:Exe @disableArgs
		$script:DisableCode = $LASTEXITCODE
	} catch {
		$script:DisableCode = 1
	}
}

# Remove-GuardrailExe: delete <dest>\guardrail.exe, retrying briefly. Windows
# cannot delete a running image (the approval daemon, say), but it can rename
# one, so a delete that keeps failing renames the binary aside instead.
function Remove-GuardrailExe {
	try {
		Invoke-WithRetry { Remove-Item -LiteralPath $script:Exe -Force }
		return
	} catch {
		$null = $_
	}
	$aside = "$($script:Exe).old"
	try {
		if (Test-Path -LiteralPath $aside) { Remove-Item -LiteralPath $aside -Force }
		Rename-Item -LiteralPath $script:Exe -NewName 'guardrail.exe.old' -Force
	} catch {
		Die 1 "cannot remove $($script:Exe)"
	}
	Say "guardrail.exe is in use; renamed to guardrail.exe.old $([char]0x2014) delete it after the next reboot"
}

# Get-DestLeftovers: list what `guardrail update` and this script left beside
# the binary (a superseded guardrail.exe.old, an update or install staging
# file).
function Get-DestLeftovers {
	foreach ($name in @('guardrail.exe.old', '.guardrail-update', '.guardrail.install.exe')) {
		$p = Join-Path $script:Dest $name
		if (Test-Path -LiteralPath $p) { $p }
	}
}

# Remove-DestLeftovers: sweep every owned leftover. A leftover still in use
# stays; it never fails the uninstall.
function Remove-DestLeftovers {
	foreach ($p in @(Get-DestLeftovers)) {
		Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
	}
}

# Uninstall-Guardrail: disable every plane, then remove the binary, the plugin
# file, the PATH entry and the Defender exclusion (and, with -Purge, every
# state root). Never downloads anything.
function Uninstall-Guardrail {
	if (-not (Test-Path -LiteralPath $script:Exe -PathType Leaf)) {
		$leftovers = @(Get-DestLeftovers)
		if ($leftovers.Count -gt 0) {
			Remove-DestLeftovers
			$left = @(Get-ChildItem -LiteralPath $script:Dest -Force -ErrorAction SilentlyContinue)
			if ($left.Count -eq 0) {
				Remove-FromPath
				Remove-Item -LiteralPath $script:Dest -Force -ErrorAction SilentlyContinue
			}
			Remove-DefenderExclusion
		}
		Say "nothing installed at $($script:Dest)"
	} else {
		if (-not $NoSetup) {
			Invoke-DisablePlanes
			if ($script:DisableCode -ne 0) { Die 1 'uninstall aborted: planes are still registered' }
		}
		Remove-GuardrailExe
		$plugin = Join-Path (Get-PluginDir $env:USERPROFILE) 'guardrail.js'
		try {
			if (Test-Path -LiteralPath $plugin) { Remove-Item -LiteralPath $plugin -Force }
		} catch {
			Die 1 "cannot remove $plugin"
		}
		Remove-DestLeftovers
		# The PATH entry goes only with the directory: anything still in <dest>
		# (another tool, or a guardrail.exe.old in use) keeps it.
		$left = @(Get-ChildItem -LiteralPath $script:Dest -Force -ErrorAction SilentlyContinue)
		if ($left.Count -eq 0) {
			Remove-FromPath
			Remove-Item -LiteralPath $script:Dest -Force -ErrorAction SilentlyContinue
		} else {
			Say "leaving $($script:Dest) on PATH (other tools live there)"
		}
		Remove-DefenderExclusion
		Say "guardrail removed from $($script:Dest)"
	}
	if ($Purge) { Remove-StateRoots }
	exit 0
}

function Invoke-Handoff {
	Cleanup
	if ($NoSetup) {
		Say "guardrail $Version installed at $($script:Exe) (setup skipped)"
		# The steps still owed to the operator (#364). Best effort: a release
		# that predates `next` answers exit 2, which must not fail the install.
		try {
			$ErrorActionPreference = 'Continue'
			$PSNativeCommandUseErrorActionPreference = $false
			& $script:Exe next 2>$null
		} catch { }
		exit 0
	}
	if ($State -eq 'disabled' -and $SetupIfInteractive -and -not (Test-InteractiveInput)) {
		Say 'setup --state disabled skipped (no interactive local terminal); run guardrail setup --state disabled from an interactive shell'
		exit 0
	}
	$setupArgs = @('setup')
	if ($State -eq 'disabled') { $setupArgs = @('setup', '--state', 'disabled') }
	if (-not (Test-SetupSupported)) {
		if ($State -ne 'disabled') { Die 1 $OldBinaryHint }
		Say "this guardrail predates 'setup'; running guardrail plane disable --all"
		$setupArgs = @('plane', 'disable', '--all')
	}
	$code = 1
	# Called bare, not piped: setup needs the console as its stdin and stdout.
	try {
		$ErrorActionPreference = 'Continue'
		$PSNativeCommandUseErrorActionPreference = $false
		& $script:Exe @setupArgs
		$code = $LASTEXITCODE
	} catch {
		[Console]::Error.WriteLine("install: guardrail setup failed to run: $_")
		$code = 1
	}
	exit $code
}

function Invoke-Main {
	try {
		Resolve-Arguments
		Resolve-Platform
		if ($Uninstall) { Uninstall-Guardrail }
		Get-InstalledVersion

		if ($State -eq 'disabled' -and -not $SetupIfInteractive) {
			# No download ever happens when disabling.
			if (-not (Test-Path -LiteralPath $script:Exe -PathType Leaf)) {
				Say "no guardrail at $($script:Exe); nothing to do"
				exit 0
			}
			if ($NoSetup) {
				Say "guardrail found at $($script:Exe) (setup --state disabled skipped)"
				exit 0
			}
			Invoke-Handoff
		}

		if ($script:Installed -ceq $Version) {
			Say "guardrail $Version already installed at $($script:Exe)"
		} elseif ($script:Installed -and (Test-VersionAtLeast $script:Installed $SelfUpdateFloor)) {
			Update-Installed
		} else {
			Install-Bootstrap
		}

		Confirm-Installed
		Add-DefenderExclusion
		Invoke-Handoff
	} catch {
		# `exit` is not catchable, so only an unanticipated error lands here.
		Die 1 "unexpected error: $($_.Exception.Message)"
	} finally {
		Cleanup
	}
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Main }
