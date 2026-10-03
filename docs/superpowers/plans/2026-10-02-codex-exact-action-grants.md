# Codex exact-action grants implementation plan

Execution: inline, following the operator's instruction to proceed.
Spec: ../specs/2026-10-02-codex-exact-action-grants-design.md

- [x] Add a private bounded request store with exact binding, 15-minute expiry,
  locked approval/revocation and atomic one-use consumption. Test mismatches,
  expiration, concurrency and filesystem failures before implementation.
- [x] Bind supported Codex commands and patches, keeping Deny and never-grantable
  rules invariant. Wire consumption before audit and request guidance after Ask.
- [x] Extend terminal grant/revoke with --record. Reuse prompt/passkey approval
  machinery and preserve enrollment requirements. Keep full action bodies out
  of audit and broker state; show them from the verified private request.
- [ ] Add real-runtime action/patch snapshots and approval retry probes on both
  OSes. Diagnose the edit-before-block report by event rather than tool result.
  Linux native snapshots passed. Windows remains blocked; see
  ../../verification/2026-10-03-issue-349-codex.md.
- [ ] Amend ADR-0027, operations and changelog; vet and full tests on both OSes;
  review, push one PR, merge on green, clean and report a release tag if cut.
