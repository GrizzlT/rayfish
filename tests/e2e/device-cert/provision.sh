#!/usr/bin/env bash
# Provision 3 Scaleway instances for the device-cert e2e test.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
SERVERS="$DIR/.servers"
NAMES=(rayfish-e2e-a rayfish-e2e-b rayfish-e2e-c)
LABELS=(srv-a srv-b srv-c)
NEXT="tests/e2e/device-cert/run.sh"

# shellcheck source=../../lib/provision.sh
source "$DIR/../../lib/provision.sh"
