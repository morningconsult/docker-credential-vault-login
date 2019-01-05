#!/usr/bin/env bash
# Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#         https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

set -e

ROOT=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
cd "${ROOT}"

if [ -z $( which go ) ]; then
	echo "Go is not installed. Please install Go before executing this script."
	exit 1
fi

if [ -z $( echo "${GOPATH}" ) ]; then
	echo "Your GOPATH is not set. Please set the GOPATH before executing this script."
	exit 1
fi

BIN_DIR="${ROOT}/${1}"
TAG="${2}"
HASH="${3}"
REPO="${4}"

cd "${ROOT}"

# Install dep if it isn't already installed
if [ -z $( which dep ) ]; then
	export GOBIN="${GOPATH}/bin"
	export PATH="${PATH}:${GOBIN}"
	curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
fi

# Fetch dependencies
dep ensure

# Set ldflags
version_ldflags="-X \"${REPO}/version.Date=$( date +"%b %d, %Y" )\""

if [[ -n "${TAG}" ]]; then
	version_ldflags="${version_ldflags} -X \"${REPO}/version.Version=${TAG}\""
fi

if [[ -n "${HASH}" ]]; then
	version_ldflags="${version_ldflags} -X \"${REPO}/version.Commit=${HASH}\""
fi

mkdir -p "${BIN_DIR}"

CGO_ENABLED=0 go build \
	-installsuffix cgo \
	-a \
	-ldflags "-s -w ${version_ldflags}" \
	-o "${BIN_DIR}/docker-credential-vault-login" \
	.
