#!/usr/bin/env bash

REPO="gitlab.morningconsult.com/mci/docker-credential-vault-login"
VAULT_VERSION="0.10.4"
VAULT_DEV_PORT="8204"
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
TEMPDIR="${ROOT}/${TEMPDIR}"

## Download Vault binary
wget --quiet -O $TEMPDIR/vault-${VAULT_VERSION}.zip https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip

## Unzip the Vault binary to /usr/loca/lbin
unzip -o $TEMPDIR/vault-${VAULT_VERSION}.zip -d $TEMPDIR

## Rename vault to vault-dev
mv $TEMPDIR/vault $TEMPDIR/vault-dev

## Start vault-dev in the background
$TEMPDIR/vault-dev server -dev -dev-listen-address="127.0.0.1:${VAULT_DEV_PORT}" &

sleep 2

## Run Go unit tests
printf "\n==> Starting Go unit tests...\n\n"
export GOPATH="$TEMPDIR"
export PATH=$PATH:$GOPATH/bin
go get -u $REPO
go test -v -ldflags="-X ${REPO}/vault.VaultDevPort=${VAULT_DEV_PORT}" -timeout 30s $REPO/vault/...
printf "\n==> Tests complete\n\n"

## Kill vault-dev
pkill vault-dev 

## Delete the temporary directory
rm -rf $TEMPDIR
