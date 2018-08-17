#!/usr/bin/env bash

set -e

ROOT=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
cd "${ROOT}"

# Builds the ecr-login binary from source in the specified destination paths.
mkdir -p $1

cd "${ROOT}"

PACKAGE_ROOT=$4

version_ldflags=""

if [[ -n "${2}" ]]; then
        version_ldflags="-X ${PACKAGE_ROOT}/vault/version.Version=${2}"
fi

if [[ -n "${3}" ]]; then
        version_ldflags="$version_ldflags -X ${PACKAGE_ROOT}/vault/version.GitCommitSHA=${3}"
fi

GOOS=$TARGET_GOOS GOARCH=$TARGET_GOARCH CGO_ENABLED=0 \
       	go build -a -ldflags "${version_ldflags}" \
       	-o $1/docker-credential-vault-login .