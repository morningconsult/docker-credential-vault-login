#!/usr/bin/env bash
# Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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

# Builds the ecr-login binary from source in the specified destination paths.
mkdir -p $1

cd "${ROOT}"

PACKAGE_ROOT=$5

version_ldflags=""

if [[ -n "${2}" ]]; then
    version_ldflags="-X \"${PACKAGE_ROOT}/vault-login/version.Version=${2}\""
fi

if [[ -n "${3}" ]]; then
    version_ldflags="${version_ldflags} -X \"${PACKAGE_ROOT}/vault-login/version.Commit=${3}\""
fi

if [[ -n "${4}" ]]; then
    version_ldflags="${version_ldflags} -X \"${PACKAGE_ROOT}/vault-login/version.Date=${4}\""
fi

CGO_ENABLED=0 go build \
    -installsuffix cgo \
    -a \
    -ldflags "-s ${version_ldflags}" \
    -o "${1}/docker-credential-vault-login" \
    ./vault-login/cli/docker-credential-vault-login