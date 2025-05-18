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

