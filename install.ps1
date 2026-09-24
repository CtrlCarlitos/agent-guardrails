# install.ps1: install an exact, checksum-verified guardrail release, then
# hand off to `guardrail setup`. Windows PowerShell 5.1 and PowerShell 7.
#
#   install.ps1 -Version <tag> [-State enabled|disabled] [-Dest <dir>]
#               [-BaseUrl <url-or-dir>] [-NoSetup]
#   install.ps1 -Help
#
# Exit codes: 2 usage / unsupported platform; 1 download, checksum, install
# or post-install version failure; otherwise the exit code of
# `guardrail setup` (0 with -NoSetup). PowerShell itself rejects unknown or
# malformed parameters (exit 1 when run with -File).
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
	[switch]$Help
)

$ErrorActionPreference = 'Stop'

# Oldest release whose `guardrail update` is the sanctioned replacement path.
# A fixed historical constant, not a pin.
$SelfUpdateFloor = 'v0.19.2-dev'
$DefaultBaseUrl = 'https://github.com/CtrlCarlitos/agent-guardrails/releases/download'

$script:Asset = ''
$script:Exe = ''
$script:Installed = ''
$script:Tmp = ''
$script:BaseIsHttp = $false

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
              [-BaseUrl <url-or-dir>] [-NoSetup]
  install.ps1 -Help

  -Version <tag>     Exact release tag, e.g. v0.23.0-dev (required; 'latest' is not supported).
  -State <state>     enabled (default) or disabled.
  -Dest <dir>        Install directory (default: $env:USERPROFILE\.local\bin).
  -BaseUrl <base>    Release base: http(s) URL, file://<dir> or a directory
                     laid out as <base>\<tag>\<asset>
                     (default: https://github.com/CtrlCarlitos/agent-guardrails/releases/download).
  -NoSetup           Stop once the binary is installed and verified; do not run `guardrail setup`.
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

# --- steps --------------------------------------------------------------------

function Resolve-Arguments {
	if ($Help) {
		Show-Usage
		exit 0
	}
	if (-not $Version) {
		Die 2 "-Version is required: pass an exact release tag such as v0.23.0-dev ('latest' is not supported)"
	}
	if (-not (Test-ValidVersion $Version)) {
		Die 2 "-Version must be an exact release tag such as v0.23.0-dev, got '$Version' ('latest' is not supported)"
	}

	if (-not $Dest) {
		if (-not $env:USERPROFILE) { Die 2 'USERPROFILE is not set; pass -Dest <dir>' }
		$script:Dest = Join-Path (Join-Path $env:USERPROFILE '.local') 'bin'
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
		Move-Item -LiteralPath $staged -Destination $script:Exe -Force
	} catch {
		Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
		Die 1 "failed to install $($script:Exe)"
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

function Invoke-Handoff {
	Cleanup
	if ($NoSetup) {
		Say "guardrail $Version installed at $($script:Exe) (setup skipped)"
		exit 0
	}
	$setupArgs = @('setup')
	if ($State -eq 'disabled') { $setupArgs = @('setup', '--state', 'disabled') }
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
		Get-InstalledVersion

		if ($State -eq 'disabled') {
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
