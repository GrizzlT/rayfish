#!/usr/bin/env bash
# Destroy the benchmark instances listed in .servers and remove the file.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SERVERS="$DIR/.servers"

# shellcheck source=../lib/teardown.sh
source "$DIR/../lib/teardown.sh"
