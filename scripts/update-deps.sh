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

# ORIGIN=$(pwd)
ORG="github.com/morningconsult"
TOOL="docker-credential-vault-login"

## Make a temporary directory
TEMPDIR=$(mktemp -d get-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${TEMPDIR}"
export PATH="${GOPATH}/bin:${PATH}"

mkdir -p "${GOPATH}/bin" "${GOPATH}/src/${ORG}"

cd "${GOPATH}"

# Install dep
echo "==> Installing dep"
curl --silent https://raw.githubusercontent.com/golang/dep/master/install.sh | sh > /dev/null

cd "${GOPATH}/src/${ORG}"
echo "Fetching ${TOOL}..."
git clone git@github.com:morningconsult/${TOOL}.git
cd ${TOOL}

## Clean out earlier vendoring
rm -rf Gopkg.* vendor

echo "==> Fetching dependencies (this may take some time)"
dep init

printf "==> Done; to commit, run: \n\n    $ cd ${GOPATH}/src/${ORG}/${TOOL}\n\n"