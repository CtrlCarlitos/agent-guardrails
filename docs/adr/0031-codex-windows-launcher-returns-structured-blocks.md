# ADR-0031: Codex Windows launcher returns structured blocks

Codex executes `commandWindows` through the session shell, which may be
PowerShell or `cmd.exe`; a command containing shell-specific control syntax
therefore cannot be portable, and an outer PowerShell converts a nested native
exit 2 into exit 1. The Windows launcher is one quote-free encoded PowerShell
command that invokes the owned wrapper, preserves successful output, and
translates nonzero evaluator results into Codex's documented event-specific
blocking JSON with exit 0. This keeps policy and handler failures fail-closed
without presenting intentional blocks as failed hooks; an unparseable event is
the exceptional case that still exits 2.
