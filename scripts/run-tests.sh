#!/usr/bin/env bash

REPO="gitlab.morningconsult.com/mci/docker-credential-vault-login"
VAULT_VERSION="0.10.4"
ROOT=$(pwd)
MACHINE=$(uname -m)
KERNEL=$(uname -s)

## Tests can only be run on 64-bit Linux machines
if [ "${KERNEL}" != "Linux" ] || [ "${MACHINE}" != "x86_64" ]; then
    echo "Tests may be run on a 64-bit Linux machine only. Exiting."
    exit 1
fi

## Make a temporary directory
TEMPDIR=$(mktemp -d vault.XXXXXX)

## Download Vault binary
wget --quiet -O $TEMPDIR/vault-${VAULT_VERSION}.zip https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip

## Unzip the Vault binary to /usr/loca/lbin
unzip -o $TEMPDIR/vault-${VAULT_VERSION}.zip -d $TEMPDIR

## Rename vault to vault-dev
mv $TEMPDIR/vault $TEMPDIR/vault-dev

## Start vault-dev in the background
$TEMPDIR/vault-dev server -dev -dev-listen-address="127.0.0.1:8204" &

## Run Go unit tests
export GOPATH=$TEMPDIR
export PATH=$PATH:$GOPATH/bin
go get -u $REPO
go test -v -timeout 30s $REPO/...

## Kill vault-dev
pkill vault-dev 

## Delete the temporary directory
rm -rf $TEMPDIR
