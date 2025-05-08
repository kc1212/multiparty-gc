#!/usr/bin/env bash

set -e
set -u

cargo build --release

first_run=0
average_over=20
for n in 5 10 15 20
do
    for circuit in "aes128" "aes256"
    do
        for protocol in "copz" "wrk17"
        do
            if [ $first_run -eq 0 ]; then
                ./target/release/multiparty-gc -n "$n" -p "$protocol" -c "$circuit" --average-over "$average_over" --show-header
                first_run=1
            else
                ./target/release/multiparty-gc -n "$n" -p "$protocol" -c "$circuit" --average-over "$average_over"
            fi
        done
    done
done