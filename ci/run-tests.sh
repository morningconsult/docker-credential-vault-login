#!/bin/sh

set -e

REPO="github.com/morningconsult/docker-credential-vault-login"

echo "==> Installing APK dependencies"

apk add -qU --no-progress make

export CGO_ENABLED=0

mkdir -p "${GOPATH}/src/${REPO}"
cp -r . "${GOPATH}/src/${REPO}"
cd "${GOPATH}/src/${REPO}" 

echo "==> Running unit tests"

make test

echo "==> Done"