#!/bin/sh

set -e

ROOT=$(pwd)
REPO="github.com/morningconsult/docker-credential-vault-login"
TEMPDIR="/tmp/docker-credential-vault-login-testing"

echo "==> Installing APK dependencies"

apk add -qU --no-progress gcc make

rm -rf $TEMPDIR
mkdir -p $TEMPDIR
export GOPATH=$TEMPDIR
export CGO_ENABLED=0

mkdir -p $GOPATH/src/$REPO

cd $GOPATH/src/$REPO

cp -r $ROOT/* .

make test

echo "==> Done"