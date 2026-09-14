# Rust implementation status

The native Rust implementation is incomplete. Production Apply is disabled, and the project is not
ready for release. Portable tests, generated schemas, and a successful Windows-target build do not
demonstrate the behavior of the application on Windows.

<a id="implemented-foundations"></a>

## Current implementation

Plans use schema `4.0`, and IPC uses protocol `2`. Profiles and result documents remain on schema
`3.0`. The public Rust `PlanV4` contract keeps `PlanV3` as a source-code alias, but that alias does
not make old saved plans valid. Schema-3 plans must be regenerated, and operators must approve the
new digest returned by the worker.

An observation is keyed by profile step ID and records the capability ID, canonical parameter
digest, and exact facts. This prevents repeated steps for the same capability from overwriting one
another. The CLI and worker share the same observation source and use the same pure functions to
derive proposed actions.

The GUI's native Review screen also uses those functions on a background thread. Review can be
cancelled between observations, but it is only a preview. It does not perform authenticated worker
approval or produce an executable saved-plan envelope.

The existing capability planners produce a finite proposal from captured observations without
repeating Windows reads. Planning fails if the required pre-state for Office or browsers, Windows
Update, or Security Options is absent. Observation-only capabilities produce explicit non-mutating
results. Several planners still omit outcomes provided by v2, so a typed proposal does not mean the
capability is complete.

Protected-install verification keeps the verified file and ancestor-directory handles open. Before
package verification or capability work, the worker waits for membership in a Job Object configured
with kill-on-close and no breakaway. This check does not yet authenticate that the Job Object is the
one created by the launcher.

Broker threads use the standard owned Windows handle type for protected-file handles. ACL checks
distinguish read and traverse permissions from permissions that can modify data. Inheritance-only
ACEs can still cause conservative rejection and therefore remain an availability concern. The worker
rejects resource metadata without an authenticated retained handle, and the handle-transfer protocol
has not been implemented.

Journal format 2 requires approval, sequential action boundaries, terminal completion, and an
immediate stop after an action fails. A failed write or synchronization makes the journal writer
unusable. If an action start reaches durable storage without a matching completion, the journal
cannot be reopened or repaired as an ordinary incomplete frame; explicit action recovery is required.
This protects the journal, but it does not provide capability rollback. Older journal formats are
rejected and retained for manual recovery. They are never converted into authority to resume work.

The protected-output API resolves the machine ProgramData known folder, creates a new run ID, uses
fixed product, run, and artifact names, creates private DACLs atomically, and retains directory
handles. It rejects an existing untrusted root instead of changing its ACL. The protected journal
sink holds the directory lease and enforces an 8 MiB quota. `Journal::create_protected` adds framing,
lifecycle, and record limits.

The sealed worker dispatcher uses this storage for the first Windows Update action path, but that
action is not admitted for production. Default ProgramData ACL compatibility and actual Windows
behavior for creation, replacement, handle retention, durability, and failures have not been tested.

The capability registry and parity ledger distinguish unavailable state acquisition from available
code. Capabilities 09, 11, and 12 still use unconditional acquisition stubs. Capability 21 reads the
fixed firewall profile defaults but does not yet cover managed isolation or the protected break-glass
resource. All four remain `in_development`; partial acquisition does not change their maturity.

## Required implementation work

- Complete native acquisition for support collection, IOC sweep, incident artifacts, and isolation.
- Match every v2 outcome, including the omitted LAPS, local administrator, service, task, Defender,
  Sysmon, package, firewall, SMB, policy, collection, and other high-impact operations.
- Implement authenticated resource-handle transfer with independent bounds and digest validation.
- Authenticate the exact launcher Job Object and complete the recovery flow used by the distributed
  application.
- Finish the checks that admit sealed actions, then execute only worker-retained typed intents.
  Generic metadata or a registry eligibility flag must never bypass execution and recovery checks.
- Extend the sealed native dispatcher beyond its first Windows Update action. Add recovery after a
  process crash, protected readers for recovery and evidence, and application delivery of committed
  result documents.
- Connect the GUI to package binding, saved-plan creation, worker proposal and approval, progress,
  authenticated results, and trusted artifact opening.
- Replace the structural PowerShell inventory with behavior comparisons for every supported outcome.
  Partial behavioral fixtures do not establish complete capability parity.
- Run Windows tests for behavior, journals, packages, and operational performance. These measurements
  must include the native protection and signature costs omitted by the portable test harness.

The remaining Windows test environments include signed packages, UAC, LocalSystem, protected and
extracted installations, process spying, accessibility, supported Windows versions and SKUs, and
hardware. Each must be run and its results retained before any capability or release status is
promoted.

<a id="local-performance-evidence"></a>

## Local performance measurements

The portable scheduler comparison covers independent, chained, and layered graphs with 32, 256,
and 1,024 actions. The current algorithm uses a dependency index instead of repeatedly scanning the
graph. It preserves the first-ready input order, error behavior, sequential execution, and
cancellation. Tests compare its order with the original algorithm for every four-node DAG and every
input permutation.

The release-mode benchmark alternates the two algorithms in the same process. The indexed version
had lower observed median and p95 preparation times for all nine workloads. Shared-host contention
limits conclusions about absolute latency. Memory was measured for the whole process, so the data
does not compare memory use between the two algorithms or say anything about Windows performance.
See [the scheduler measurements](performance/scheduler.md).

Separate portable processes measure journal, evidence, and package round trips. The workloads retain
synchronous writes, hashes, quotas, and integrity checks. Their test-only protection and signature
ports omit the cost of Windows security APIs. See [the I/O measurements](performance/io-costs.md).

<a id="windows-update-execution-foundation"></a>

## Windows Update execution status

The fixed registry adapter accepts typed fields and values, compares the immediate pre-state, flushes
each write, and reads the result independently. A registry write can succeed even if a later step
reports failure.

The sealed worker dispatcher consumes an opaque approval token once, keeps the installation proof
alive throughout execution, and accepts one Windows Update intent retained by the worker. Production
use remains disabled until containment, the distributed recovery path, and Windows execution have
been verified.

The adapter opens existing keys without following registry links and retains their handles. Missing
keys are rejected because atomic creation of protected keys has not been implemented. Every retained
registry path segment is checked for owner, DACL, and the name reported by the kernel. Those checks
run again before mutation and after the flush. Readback checks the retained leaf, then opens the
fixed path independently and checks it again.

Inheritance-only writer ACEs can still cause a conservative rejection. Windows tests for ACLs,
registry links, kernel-reported names, flushing, replacement races, and readback have not been run.
Portable tests and Windows-target compilation cannot satisfy those requirements.

The `allow_microsoft_update` profile setting remains catalog metadata. It no longer proposes an
extra registry write that v2 does not perform. Changing this setting does not authorize a mutation.

The worker retains capability-owned semantic values alongside the proposal shown for review and
compares the serialized review metadata. Approval rejects read-only or mismatched variants and
actions without complete execution and recovery contracts. The native-handler registration type
cannot be deserialized from JSON.

The action implementation validates the complete exact preconditions and a canonical finite plan.
It writes a protected manual-recovery snapshot, durably records the action start, applies ordered
compare-and-set mutations, observes the post-state independently, and writes a terminal receipt.
A failed mutation stops subsequent writes. A journal failure blocks all further journal I/O. If the
post-state is unknown, the unmatched start remains in the journal for manual recovery. The system
does not claim automatic rollback. It checks for cancellation before starting the action.

The CLI and worker exchange authenticated progress messages and support cooperative cancellation,
but this path still needs live Windows verification. When approval revalidation fails, the worker
returns an authenticated rejection bound to the proposal. Rejections caused by invalid input, trust,
freshness, or preconditions remain distinct from failures during execution.

A result artifact is added to the authenticated manifest only after a matching `RunFinished` record
has been written durably. If that append fails, the pending file remains on disk but is excluded from
the committed manifest. A reader in the distributed application must verify the file's terminal
journal binding before accepting it. The implementation does not provide multi-capability execution
or the complete recovery flow.

## Partial isolation preflight

Capability 21 reads the default inbound and outbound actions for the Domain, Private, and Public
firewall profiles through the existing Windows Firewall COM boundary. CLI and GUI Audit accept this
partial observation while the capability remains `in_development`. Missing, denied, or unparsed
fields leave the observation incomplete; an unavailable provider fails the observation. Managed
isolation state and the protected break-glass source have not been run.

The pure planner requires one complete snapshot for each profile, a known inactive managed marker,
and a verified break-glass digest when requested. It emits only defaults that need to change, in a
fixed profile order. A default that is already blocked produces no change. An incomplete preflight
records typed blockers and cannot produce an executable proposal through the shared planner. Raw
Apply is rejected before it reaches platform access.

The implementation still lacks firewall enablement and effective-rule checks, Group Policy
writability checks, trusted acquisition of the marker and resource, mutation, readback, recovery,
and live Windows tests. Default actions alone do not prove that a host is effectively isolated.

## Committed result reading

The engine can read a fixed protected result and journal by using the storage UUID from an
authenticated worker manifest. It compares the canonical result bytes, identity, receipts, and
earlier artifacts with that manifest. It then verifies the complete journal chain, approval, action
records, terminal commit, prefix hash, and authenticated terminal anchor.

The reader rejects a pending file, partial journal, alternate journal encoding, substituted receipt,
or mismatched result. Writer and reader use the same strict internal result-document schema. This is
a read-only API; it grants neither recovery nor execution authority.

On Windows, the reader retains handles to the protected ancestors, run directory, result file, and
journal file while it performs bounded reads. It validates the owner, DACL, final identity, reparse
status, and single-link status without changing permissions. A standard-user read can fail because
the run DACL is private. The API compares references to other artifacts but does not read their
contents. GUI delivery, recovery-document opening, and live Windows tests for ACL and replacement
races are unfinished.

## Authenticated progress and cancellation

While waiting for the worker, the CLI installs a scoped Ctrl-C and Ctrl-Break handler. It sends one
empty cancellation request bound to the exact approval, then continues waiting for an authenticated
terminal result. Progress messages must use a known finite stage and refer to proposed action IDs;
they cannot replace the terminal result.

One worker thread owns the named pipe while a scoped executor thread consumes approval through the
sealed dispatcher. Invalid control traffic aborts the exchange and requests cooperative cancellation.
Both peers limit the lifetime and number of control messages without evicting accepted nonces during
that window. All pending progress is sent before the terminal result, and outbound writes use the time
remaining in the session deadline.

The Windows pipe uses overlapped operations and message-read mode. Cancellation must finish before
its buffers are released. A receive may be retried only after a clean timeout that consumed no prefix
bytes. Partial reads and failed writes make the connection unusable.

This behavior is covered by code inspection and portable tests. Native I/O cancellation, cleanup of
pending operations, console behavior, peer disconnects, and progress ordering still require Windows
execution. The session deadline does not interrupt an active native action. The launcher's earlier
two-minute process limit can terminate a worker that is still running, so exact launcher containment
and crash or manual-recovery behavior remain release requirements. GUI approval and cancellation are
also unfinished.

<a id="local-verification-checkpoint-on-2026-09-08"></a>

## Checks run on 2026-09-08

The repository passed formatting with Rust 1.96.0, strict Clippy on the host and Windows target,
warning-free rustdoc, generation and snapshot verification, cargo-deny 0.20.2, and the Rust quality
gate. The portable suite passed 471 tests. Its four opt-in performance tests ran separately in
release mode for the earlier recorded measurements; the newer control and reader changes were not
benchmarked. Documentation and diff whitespace checks also passed.

The focused PowerShell comparison suite passed three tests. Those tests cover all four DoH, seven
Windows Update, five Security Options, and five PowerShell Logging behavioral cases. The other 48
capabilities have structural comparison data only.

The Pester checks used the installed PowerShell 7.5.4 runtime. The full PowerShell gate stopped at
its runtime-version check because it requires 7.6.3, so none of the later checks in that run executed.
These results do not replace the required PowerShell 7.6.3 or Windows PowerShell 5.1 runs.

Independent source reviews examined journal lifecycle and durability, registry controls,
protected-output boundaries, opaque approval lifetime, sealed dispatch, authenticated rejections,
result-document commit ordering, committed-result readers, and the partial isolation preflight.
Defects found in those reviews were fixed and covered by regression checks. The reviews do not
demonstrate live Windows behavior or complete the 52-capability implementation.
