# Opt-in hook timing implementation plan

**Goal:** Implement #530's approved instrumentation proposal without changing #460's architecture.

**Architecture:** GUARDRAIL_TIMING=1 enables bounded diagnostic samples. Native hook and daemon samples share session/call IDs with audit; plugin samples correlate against those IDs for actual engine version. Monotonic durations measure only code-owned boundaries. Host launch and unobservable wrapper phases are null, never inferred from residuals.

**Spec:** #530 and its 2026-11-15 evidence/proposal, explicitly approved for implementation by the operator.

**Constraints:** Default emits no new timing traces, including slow/failure paths; legacy hook_ms/startup_ms audit fields remain compatible. At most 200 bounded records per timing file. Diagnostics never affect verdicts. No commands, arguments or environment content in timing records. No config-based shell inference; #501 is evidence/handoff only. Signed conventional commit; full build/vet/tests on native Windows and Linux before every push.

- [x] RED: successful fast plugin calls missing traces, default failures unexpectedly traced, hook/audit correlation and independent phases missing.
- [x] GREEN: audit timing record/logger with nonblocking locking, size/sample bounds and regular-file protection; hook engine/dial/response measurements; daemon evaluator and response measurements; plugin dispatch/dial/attempt measurements and opt-in gating.
- [x] RED/GREEN: doctor reports separate host/version/transport/sample-kind groups; missing phases explicitly unmeasured, plugin version joined only by exact session/call identity. Test old/missing/malformed records and bounded storage.
- [ ] Verify unchanged allow/deny output with opt-in off/on, daemon and fallback paths, full Windows/Linux suites. Inline review; independent review only if available under active guardrail rules.
- [ ] Publish root cause/evidence to #530 before one signed PR, watch every required check, merge once authorized and green, confirm merge, remove only this task's worktree/branch.
- [ ] Build merged binary without replacing the installation; repeat matched benign native envelopes and real plugin calls on Windows with no concurrent suite load; post per-phase/per-host results and unmeasured fields on #530. Capture engine binary version explicitly and exclude invalid inputs.

Review focus: contention drops samples rather than delaying policy; diagnostic write failures leave verdicts unchanged; reused call IDs require session+call correlation; missing host versions stay unmeasured; disk growth is bounded even for long identities. No independent host-start timer is available inside a child process.

Inline review: oversized/malformed retained rows fixed after RED tests in both writers; timing destination failure preserves allow/deny output. Daemon observation fixture passed 30 repetitions. Independent reviewer blocked by Guardrail; tracked in #587.

First full Windows run found the real append-only-handle truncation failure:
fixed the snapshot writer to use O_RDWR with the same regular-file/identity
checks. Native Windows storage fixtures then passed. The daemon fixture raced
the post-response observer and contended with optional client sampling; use a
direct client and wait for both strict phase observations. Three native Windows
timing repetitions passed after these fixes. Linux timing/source-table fixtures
passed too. Main's concurrent #584/#586 integration left P1.net-stack absent
from the generated rule-source index; regenerate that one derived entry, without
changing the test or the rule. Full suites must run again on this final tree.
