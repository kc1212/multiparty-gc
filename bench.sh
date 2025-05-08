#!/usr/bin/env bash

set -e
set -u

cargo build --release

first_run=0
average_over=10
for latency in 1 50 # 1 ms for LAN, 50 ms for same continent
do
    # for n in 5 10 15 20
    for n in 5 10
    do
        for circuit in "aes128" "aes256"
        do
            for protocol in "copz" "wrk17"
            do
                if [ $first_run -eq 0 ]; then
                    ./target/release/multiparty-gc -n "$n" -p "$protocol" -c "$circuit" --latency-ms "$latency" --average-over "$average_over" --show-header
                    first_run=1
                else
                    ./target/release/multiparty-gc -n "$n" -p "$protocol" -c "$circuit" --latency-ms "$latency" --average-over "$average_over"
                fi
            done
        done
    done
done