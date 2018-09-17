#!/bin/sh

set -e

ROOT=$(pwd)
REPO="github.com/morningconsult/docker-credential-vault-login"
TEMPDIR="/tmp/docker-credential-vault-login-testing"

echo "==> Installing APK dependencies"

# apk add -qU --no-progress \
#   openssh curl git jq sudo gcc

rm -rf $TEMPDIR
mkdir -p $TEMPDIR
export GOPATH=$TEMPDIR

mkdir -p $GOPATH/src/$REPO

cd $GOPATH/src/$REPO

cp -r $ROOT/* .

go test -v -cover  $(go list ./vault-login/... | grep -v testing)

cd $ROOT

rm -rf $TEMPDIR

echo "==> Done"