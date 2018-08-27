#!/usr/bin/env bash

set -e

ROOT=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
cd "${ROOT}"

VERSION=$1
GITCOMMIT_SHA=$2

CODE=$(
cat << EOM
package version

// Version indicates which version of the binary is running.
var Version = "${1}"

var GitCommitSHA = "${2}"
EOM
)

echo "${CODE}" > ${ROOT}/vault-login/version/version.go
