# Keep Go's build cache in the sandbox's writable temporary directory.
if ($args.Count -eq 0 -or $args[0] -notin @('test', 'vet')) {
    Write-Error 'Usage: codex-go-check.ps1 test|vet [Go arguments]'
    exit 2
}

$env:GOCACHE = Join-Path ([System.IO.Path]::GetTempPath()) 'guardrail-codex-go-cache'
go @args
exit $LASTEXITCODE
