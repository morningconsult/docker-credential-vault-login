#!/bin/sh
set -eux

readonly PROJECT="github.com/morningconsult/docker-credential-vault-login"
readonly GORELEASER_VERSION=v0.88.0

echo "==> Installing APK dependencies"

apk add -qU --no-progress \
  make \
  bash \
  git \
  gnupg

echo "==> Installing goreleaser $GORELEASER_VERSION"

wget --quiet -O /tmp/goreleaser.tar.gz https://github.com/goreleaser/goreleaser/releases/download/${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz
tar xzf /tmp/goreleaser.tar.gz -C /tmp
mv /tmp/goreleaser /usr/local/bin

mkdir -p "${GOPATH}/src/${PROJECT}"
cp -r . "${GOPATH}/src/${PROJECT}"
cd "${GOPATH}/src/${PROJECT}"

echo "==> Running unit tests"

export CGO_ENABLED=0
make test

goreleaser release \
  --rm-dist \
  --skip-sign
