#!/usr/bin/env bash

set -e

# Normalize to working directory being build root (up one level from ./scripts)
ROOT=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
cd "${ROOT}"

export PATH=$PATH:$ROOT/scripts/generate

go generate -x $(go list ./vault-login/... | grep -v testing)