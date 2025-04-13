# multiparty-gc

This is a proof concept implementation of the WRK17 and COPZ25 garbling scheme.

## Profiling

On Linux, make sure [`perf`](https://www.brendangregg.com/perf.html) and
[`flamegraph`](https://github.com/flamegraph-rs/flamegraph)
are installed.

Then you can run the profiler and produce a flamegraph like so

```
cargo flamegraph --freq 200 --bench mybench  -- --bench <benchmark_name> --profile-time 30
```

where `<benchmark_name>` are `copz aes`, for example.
The result will be written to `flamegraph.svg` which can be opened in Firefox.
More performance can be achieved with
`RUSTFLAGS="-C target-cpu=native"`.
