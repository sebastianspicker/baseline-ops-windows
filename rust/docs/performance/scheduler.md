# Scheduler preparation measurements

This benchmark measures dependency preparation on macOS. It does not include Windows capability
execution and cannot establish a performance improvement on Windows.

The original implementation first ran by itself to record a release-mode baseline. A paired run
then alternated the unchanged original algorithm and the indexed algorithm against the same
deterministic inputs in one process. Each algorithm received ten warmups and 100 measured samples.
Input order was reversed, and layered graphs used eight actions per layer. The benchmark checked
every returned order against the original implementation.

| Actions | Graph | Original median (ms) | Indexed median (ms) | Original p95 (ms) | Indexed p95 (ms) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 32 | independent | 0.0084 | 0.0020 | 0.0086 | 0.0021 |
| 32 | chain | 0.0165 | 0.0033 | 0.0166 | 0.0035 |
| 32 | layered | 0.0189 | 0.0087 | 0.0240 | 0.0106 |
| 256 | independent | 0.8712 | 0.0163 | 1.6634 | 0.0275 |
| 256 | chain | 1.9486 | 0.0336 | 2.8755 | 0.0419 |
| 256 | layered | 2.0869 | 0.1221 | 2.9846 | 0.1562 |
| 1024 | independent | 18.5506 | 0.0645 | 22.9124 | 0.0911 |
| 1024 | chain | 48.2140 | 0.1430 | 100.0224 | 0.1731 |
| 1024 | layered | 57.6674 | 0.7009 | 125.5029 | 1.7134 |

The paired process reached 8,224,768 bytes of maximum resident memory and a 3,014,992-byte peak
memory footprint according to macOS `/usr/bin/time -l`. Those values exclude compilation and cover
both implementations together. They do not compare memory use between the algorithms. The index
adds storage proportional to the number of actions and dependency edges.

The host was shared and experienced contention, especially for the larger graphs. Within this run,
the indexed implementation had a lower median and p95 preparation time for all nine workloads. The
results do not provide a production latency guarantee. This benchmark does not measure evidence,
journal, package, or Windows runtime costs.

Tests compare ordering and errors across all 64 possible edge sets for a four-node DAG and all 24
input permutations. They also cover duplicate edges, missing dependencies, duplicate IDs, self
cycles, and disconnected cycles. Mutation remains sequential, and the existing fail-fast and
cancellation tests pass.

Run the benchmark from `rust/`:

```text
cargo test --release -p baselineops-engine scheduler_preparation_distribution -- --ignored --nocapture
```

To measure memory, run the test executable reported by Cargo under `/usr/bin/time -l`. Timing Cargo
itself also measures compilation. The [measurement record](scheduler-2026-09-07.json) contains the
full percentiles, earlier baseline, source hashes, and limitations.
