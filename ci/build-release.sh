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

set -eu

readonly PROJECT="github.com/morningconsult/docker-credential-vault-login"
readonly GORELEASER_VERSION=v0.95.2

echo "==> Installing APK dependencies"

apk add -qU --no-progress \
  make \
  bash \
  git \
  gnupg \
  curl

echo "==> Installing goreleaser $GORELEASER_VERSION"

wget --quiet -O /tmp/goreleaser.tar.gz https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz
tar xzf /tmp/goreleaser.tar.gz -C /tmp
mv /tmp/goreleaser /usr/local/bin

mkdir -p "${GOPATH}/src/${PROJECT}"
cp -r . "${GOPATH}/src/${PROJECT}"
cd "${GOPATH}/src/${PROJECT}"

echo "==> Installing dep"

make install_dep

echo "==> Fetching dependencies. This may take some time."

dep ensure -vendor-only

echo "==> Creating a new non-root user"

readonly new_user="foobar"
readonly new_group="foo"

addgroup -S $new_group && adduser -S $new_user $new_group
chown $new_user:$new_group -R "${GOPATH}/src/${PROJECT}"

echo "==> Running unit tests"

su $new_user -s /bin/sh -c 'CGO_ENABLED=0 make test'

echo "==> Running unit tests"

goreleaser release \
  --rm-dist
