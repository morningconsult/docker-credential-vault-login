#!/usr/bin/env bash

ROOT=$(pwd)

VERSION=$(git tag -l *.*.* | tail -n1)

CODE=$(
cat << EOM
package version

// Version indicates which version of the binary is running.
var Version = "${VERSION}"
EOM
)

echo "${CODE}" > ${ROOT}/vault/version/version.go
