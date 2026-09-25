# ADR-0031: Codex Windows launcher returns structured blocks

Codex executes `commandWindows` through the session shell, which may be
PowerShell or `cmd.exe`; a command containing shell-specific control syntax
therefore cannot be portable, and an outer PowerShell converts a nested native
exit 2 into exit 1. The Windows command is one quote-free encoded PowerShell
launcher, which invokes the owned batch wrapper without reading or piping
stdin. The evaluator therefore inherits Codex's original JSON bytes instead
of receiving the UTF-8 byte-order mark that Windows PowerShell adds at a
native pipeline boundary. For configured Windows launchers, the evaluator returns Codex's
documented event-specific blocking JSON with exit 0 for policy decisions.
Transport and handler failures remain nonzero and fail closed.
