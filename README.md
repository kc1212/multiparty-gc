# Row Reduction Techniques for n-Party Garbling

This is a proof concept implementation of the
[COPZ25](https://eprint.iacr.org/2025/829) garbling scheme (only the
authenticated variant, not the HSS17 variant).  We also give an implementation
of [WRK17](https://eprint.iacr.org/2017/189) for comparison.

## Running and testing

To run the tests, simply use

```
cargo test
```

We provide a command line tool to simulate our garbling scheme for various
circuits. For more information, please see

```
cargo run --release -- -h
```

## Preprocessing

Two preprocessors implement the same `Preprocessor` trait (see `src/prep`):

- `InsecurePreprocessor` (default, `--prep insecure`): a simulated trusted
  dealer, every party derives the material of all parties from a shared seed.
  Only meant for benchmarking the garbling.
- `SecurePreprocessor` (`--prep secure`): the maliciously secure preprocessing
  of [WRK17](https://eprint.iacr.org/2017/189) following
  [emp-agmpc](https://github.com/emp-toolkit/emp-agmpc). It uses KOS correlated
  OT from `ocelot`, the Π_aBit^n / Π_aShare consistency checks, Π_LaAND leaky
  AND triples and bucketing. Values that the paper broadcasts use echo
  broadcast and every opening is MAC-checked. The statistical security
  parameter can be set with `--rho` (1–128, default 40). Bucket sizes are
  derived from this parameter and the actual triple count; `--bucket-size` may
  increase the calculated minimum, but smaller sizes are rejected. The
  constructor returns an error for invalid parameters or overflowing material
  sizes.

## Networking

All communication goes through the session-based network layer in `src/net`.
Every party runs `driver::run_party`, the preprocessor uses its own session.
The command line tool runs all parties in one process over the in-memory
transport; `--latency-ms` and `--bandwidth-mbps` set the one-way latency and
bandwidth of every link.

To run the parties as separate processes over QUIC (mutual TLS 1.3 with a
pinned certificate per party), first generate certificates, keys and a
configuration, then start one process per party. The last party is the
evaluator, it checks the output and prints the CSV line.

```
cargo run --release -- gen-config -n 3 --dir quic --base-port 7000
cargo run --release -- -n 3 -p copz -c aes128 --prep secure \
    --party-id 0 --config quic/parties.conf --key quic/party0.key.pem
```

Each line of `parties.conf` is `<party id> <address> <certificate file>`. In
this mode `prep_bytes` and `online_bytes` only count the evaluator's traffic.

On Unix, generated key files are owner-readable/writable only, and new configuration
directories are private. The generator refuses to overwrite existing identities.

The CSV output reports `prep_duration` (the function-independent
preprocessing, not part of `total_duration`), and the bytes sent by all
parties on the preprocessing session (`prep_bytes`, which includes the
openings during garbling) and in the online phase (`online_bytes`).

## Profiling

On Linux, make sure [`perf`](https://www.brendangregg.com/perf.html) and
[`flamegraph`](https://github.com/flamegraph-rs/flamegraph) are installed.

Then you can run the profiler and produce a flamegraph like so

```
cargo flamegraph --freq 200 --bench mybench  -- --bench <benchmark_name> --profile-time 30
```

where `<benchmark_name>` are `copz aes`, for example.  The result will be
written to `flamegraph.svg` which can be opened in Firefox.  More performance
can be achieved with `RUSTFLAGS="-C target-cpu=native"`.

## Disclaimer
This implementation is purely for academic purposes and not meant for production.

## License
This software is distributed under the **BSD-3-Clause-Clear** license.

