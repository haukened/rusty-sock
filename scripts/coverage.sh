#!/usr/bin/env sh
# Generate lcov.info for the library and fail unless every line is covered.
#
# Line totals are computed from unique DA records (the same data Codacy
# ingests); llvm-cov's own LF/LH totals double-count generic instantiations.
set -eu

cargo llvm-cov --ignore-filename-regex '(src/main\.rs|tests/)' --lcov --output-path lcov.info "$@"

awk -F'[:,]' '
  /^SF:/ { file = $2 }
  /^DA:/ {
    key = file ":" $2
    if (!(key in hit)) hit[key] = 0
    if ($3 > 0) hit[key] = 1
  }
  END {
    total = 0; covered = 0
    for (k in hit) { total++; if (hit[k]) covered++; else print "uncovered: " k }
    printf "line coverage: %d/%d\n", covered, total
    exit (covered == total) ? 0 : 1
  }' lcov.info
