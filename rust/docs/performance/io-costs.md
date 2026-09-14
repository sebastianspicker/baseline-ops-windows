# Portable journal, evidence, and package costs

These measurements show the cost of representative journal, evidence, and package operations. They
are not a before-and-after performance comparison.

Each category ran in a separate process on an Apple M4 Mac with macOS 26.6.2 and Rust 1.96.0, using
the workspace release profile. Every workload ran three warmups followed by 25 measured repetitions.
The processes ran one after another on a shared host, and caches were not cleared. Percentiles use
the nearest-rank method.

| Workload | Median (ms) | p95 (ms) | p99 (ms) |
| --- | ---: | ---: | ---: |
| Journal, 32 actions / 66 records | 270.72 | 291.37 | 296.68 |
| Evidence, 4 KiB | 25.75 | 29.15 | 29.17 |
| Evidence, 1 MiB | 29.67 | 39.76 | 40.24 |
| Evidence, 16 MiB | 116.00 | 130.31 | 139.64 |
| Package payload, 4 KiB | 35.16 | 37.08 | 37.15 |
| Package payload, 1 MiB | 38.71 | 47.84 | 49.75 |
| Package payload, 16 MiB | 114.41 | 121.24 | 147.87 |

The journal workload creates a temporary directory and a new format-2 journal, writes approval,
writes 32 start and completion pairs in sequence, finalizes the run, verifies the full hash chain
and lifecycle, and removes the temporary files. It does not perform a registry operation. Every
record append includes a flush and synchronous durability.

The evidence workload creates a protected store through a test implementation of the protection
interface. It writes one bounded artifact, persists the manifest, checks the digest, reopens the
store, verifies the complete manifest and artifact, and cleans up. Input buffers are allocated
before timing begins. This fixture does not measure Windows ACL creation or validation.

The package workload takes the same package snapshot used by production code, streams file hashes,
extracts within configured limits, validates the inventory, runs fixture signature checks, and
removes the extracted files. ZIP creation happens before timing begins. Each archive uses Stored
compression and contains three small, inert executable fixtures plus a payload of the size shown in
the table.

The detached-signature fixture checks a digest. Neither signature fixture performs cryptographic
signature verification or certificate-chain validation, and production signature verification has
not changed. These results cannot predict the total cost of verifying a signed Windows package.

| Process | Maximum resident set (bytes) | Peak memory footprint (bytes) |
| --- | ---: | ---: |
| Journal | 7,897,088 | 2,261,304 |
| Evidence, all three sizes | 44,580,864 | 38,977,896 |
| Package, all three sizes | 26,034,176 | 20,382,056 |

Memory values come from `/usr/bin/time -l` around each test executable and exclude compilation.
They include the test harness, input construction, warmups, every payload size in that category,
and cleanup. They are whole-process measurements, not per-operation allocation data or a
before-and-after memory comparison.

The [machine-readable measurements](io-costs-2026-09-07.json) include exact nanosecond results,
source hashes, and workload parameters. Build with
`cargo test -p baselineops-engine --release --no-run`. Then run each test separately with
`--exact --ignored --nocapture` and its full name:

- `boundary_io_bench::journal_io_distribution`
- `boundary_io_bench::evidence_io_distribution`
- `boundary_io_bench::package_io_distribution`

Windows filesystem durability, registry operations, protected directories, signatures, and
end-to-end latency still need to be measured on the target platform.
