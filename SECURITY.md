# Security Policy

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability**
(<https://github.com/CtrlCarlitos/agent-guardrails/security/advisories/new>).

Please do not open a public issue for a policy bypass, a secret-path leak, or a
flaw in the approval flow. A public report of a guardrail bypass is a working
exploit for everyone running the affected version.

## Supported versions

Only the latest release is supported.

## Verifying a release

Release binaries carry build-provenance attestations tying them to the
workflow run that built them:

    gh attestation verify guardrail_linux_amd64 -R CtrlCarlitos/agent-guardrails

`SHA256SUMS` in the same release checks integrity; the attestation checks origin.
