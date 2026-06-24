#!/usr/bin/env bash
# Provision 2 Scaleway instances for the rayfish throughput/latency benchmark.
#
# Both servers are placed in the SAME zone so the direct (public-IP) path is
# fast and low-latency — the benchmark then isolates the overhead rayfish adds
# on top of the raw network rather than measuring inter-region distance.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SERVERS="$DIR/.servers"
NAMES=(rayfish-bench-a rayfish-bench-b)
LABELS=(srv-a srv-b)
NEXT="tests/bench/run.sh"

# shellcheck source=../lib/provision.sh
source "$DIR/../lib/provision.sh"
