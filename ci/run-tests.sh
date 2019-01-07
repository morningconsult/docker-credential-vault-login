#!/bin/sh
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

readonly REPO="github.com/morningconsult/docker-credential-vault-login"

echo "==> Installing APK dependencies"

apk add -qU --no-progress make curl git

echo "==> Installing dep"

make install_dep

export CGO_ENABLED=0

mkdir -p "${GOPATH}/src/${REPO}"
cp -r . "${GOPATH}/src/${REPO}"
cd "${GOPATH}/src/${REPO}" 

echo "==> Fetching dependencies"

dep ensure

echo "==> Creating a new non-root user"

readonly new_user="foobar"
readonly new_group="foo"

addgroup -S $new_group && adduser -S $new_user $new_group
chown $new_user:$new_group -R "${GOPATH}/src/${REPO}"

echo "==> Running unit tests"

su $new_user -s /bin/sh -c 'CGO_ENABLED=0 make test'

echo "==> Done"
