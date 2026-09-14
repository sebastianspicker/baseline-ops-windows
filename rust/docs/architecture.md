# Architecture and trust model

The applications assemble the engine and the supporting crates. The engine depends on the domain,
capabilities, and Windows-boundary crates. The Windows crate implements contracts defined by the
capabilities and domain crates, while capabilities depend only on the domain. Domain types have no
dependency on Windows or presentation code.

The capability registry is compiled into the binaries. It does not load plugins, libraries,
scripts, or command text at runtime.

JSON is the authoritative v3 representation. Console output, JSON Lines, and flattened CSV are
views of `ResultV3`. Every input is read as bounded UTF-8 and validated against a closed schema.
Profiles contain typed parameters and dependencies, never raw command lines or arbitrary executable
arguments.

## Operation separation

BaselineOps separates observation, approval, and privileged changes:

1. `audit` observes endpoint state. It writes only requested reports or evidence artifacts.
2. `plan` observes the same state and produces ordered typed actions. Each action records its
   preconditions, digests, expiry, host binding, required privilege, risk, reversibility, and reboot
   behavior.
3. `apply` launches a short-lived elevated worker. The standard-user broker opens the profile,
   reads it within the byte limit, and sends those exact UTF-8 bytes over authenticated IPC. The
   worker never reopens the profile path. It validates the source digest, repeats the observations,
   and derives the actions itself instead of trusting action bytes from the saved plan. The worker
   retains that proposal, returns its canonical digest for review, and accepts only a second message
   that approves the same digest.

Even after approval, the worker does not currently admit capability mutations. Runtime trust checks
and required Windows tests are still incomplete. Saved plans bind external resources by digest,
but Apply also requires authenticated transfer of protected read-only handles. That transfer has
not yet been implemented, so resource-dependent mutations are rejected.

Before doing capability work, the worker must validate its protected installation and Authenticode
signer. The standard-user and elevated processes communicate over a mutually authenticated,
ACL-restricted named pipe. The worker records actions in an append-only journal under the
API-resolved `%ProgramData%\BaselineOps\Runs` directory.

The two-message approval protocol, pipe authentication, authenticated installed-package inventory,
and subject-plus-SPKI signer pinning are implemented in code. They still need signed Windows UAC,
DACL, package, and signer fixtures. The first sealed Windows Update action can create a protected
journal and recovery snapshot, but it is not admitted for production. Exact launcher Job Object
identity also remains unverified. Cancellation is checked only between actions, Apply stops on the
first failure, and rollback is available only for capabilities with a tested reversible action.

Protected-install checks keep handles to the package root, executable, and ancestor directories
through launch. Before capability work, the bootstrap waits until the process belongs to a native
Job Object configured with kill-on-close and no breakaway. Tests for exact launcher-job identity,
Windows replacement and ACL races, and retained resource-handle transfer are still required.
Resource metadata by itself cannot authorize input to the worker.

<a id="bounded-foundation-apis"></a>

## Bounded I/O and storage APIs

Resource digests are calculated from a validated, retained file handle with a 64 KiB buffer. Reads
of individual files and directory entries enforce the configured byte limit and record the actual
byte count. This avoids unnecessary buffering during audit and planning. It does not satisfy the
protected resource-transfer requirement for Apply.

Journal operations default to a 64 MiB file limit and 4,096 complete records. Trusted library
callers can supply explicit `JournalLimits` through the additive limit-aware APIs. The 4 MiB frame
limit, canonical record format, hash chain, terminal-anchor verification, and synchronous durability
remain unchanged. Worker journals in protected storage also have an 8 MiB quota.

Journal format 2 rejects older formats. It requires approval before actions, sequential action
starts and completions, and a terminal run-completion record. Recovery may remove an incomplete
tail only before terminal completion and only when no action start is left unmatched. An interrupted
action requires manual recovery; journal repair never authorizes a retry. Corrupt records and
journals outside the selected limits are rejected.

Canonical digests feed the existing canonical value serialization directly into SHA-256. The public
API that returns canonical bytes remains available, and both paths use identical serialization and
digest rules.

Evidence manifests keep locator order deterministic by inserting entries in sorted order. If
persistence fails, the store restores the previous manifest. If that rollback also fails, the same
store handle refuses further artifact reads and writes until a new open verifies the persisted
artifacts. These journal and evidence APIs are implemented, but production Apply remains disabled.

The worker's opaque approval token borrows the retained installation proof and can be consumed only
once by the sealed dispatcher. The first action implementation checks the exact pre-state again,
saves recovery data, durably records the start, updates a finite set of typed registry fields,
observes the resulting state independently, and durably records completion. Any failure stops the
action sequence.

A result document is pending until a durable `RunFinished` record binds its identifier and canonical
digest. If the final journal append fails, a result file left on disk cannot be accepted as complete.
Authenticated broker rejections remain bound to the worker's proposal, including cases where live
approval revalidation fails.

The CLI and worker exchange a finite set of authenticated progress messages and an empty cancellation
request bound to the approved digest. The named-pipe owner polls bounded overlapped reads while a
scoped executor thread retains native authority. It drains progress before returning the terminal
result, and a failed transport requests cooperative cancellation. Buffers and operation storage
remain alive after cancellation until Windows reports native completion.

GUI integration, recovery discovery in the distributed application, and Windows interruption tests
remain unfinished. The launcher's process timeout begins before approval and can expire before the
later control deadline. An action interrupted this way requires manual recovery.

## Native tools

BaselineOps never starts a command shell. A capability adapter may run one absolute native
executable only when it supplies an exact token policy, deadline, output limits, a capability-specific
parser, and mandatory source identity. Product and vendor tools must match an exact SHA-256 digest.

Fixed tools from Windows System32 must stay under the API-resolved, protected System32 directory,
have exactly one hard link, pass owner, DACL, ancestor, and WinVerifyTrust checks, and match the exact
Microsoft Windows publisher subject. A timeout or truncated output is an error. Windows APIs are
preferred. Any native-tool use, including localized or signed Windows fixtures, is recorded in the
parity ledger.

## Release identity

Rust releases use `rust-v*` tags and cannot trigger the legacy `v*` workflow. A release resolves the
exact tagged commit and produces signed x64 binaries, schemas, examples, documentation, an SBOM, a
per-file manifest, and SHA-256 records. The release job refuses to replace existing assets.

The committed-result reader accepts only an independently authenticated worker result as its
expected binding. It resolves the canonical storage UUID and the fixed `result.json` and `journal.v2`
filenames under the protected run root. The Windows boundary keeps directory and read-only file
handles open during bounded reads. The engine requires canonical bytes and verifies the complete
journal, matching action receipts, and durable `RunFinished` record before returning the result.

A result file without that terminal commit remains pending. This reader does not authenticate
arbitrary JSON supplied by a caller, grant recovery authority, or loosen private run ACLs so a
standard-user process can present the file.
