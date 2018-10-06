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
