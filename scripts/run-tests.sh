#!/usr/bin/env bash

get_available_port () {
    local LOWERPORT
    local UPPERPORT

    read LOWERPORT UPPERPORT < /proc/sys/net/ipv4/ip_local_port_range

    local FILE1=$(tempfile)
    local FILE2=$(tempfile)
    local FILE3=$(tempfile)

    seq "$LOWERPORT" "$UPPERPORT" | sort > $FILE1
    ss -tan | awk '{print $4}' | cut -d':' -f2 | grep '[0-9]\{1,5\}' | sort -u > $FILE2

    comm -23 $FILE1 $FILE2 > $FILE3

    local OPEN_PORT=$(shuf -n1 $FILE3)
    rm -f $FILE1 $FILE2 $FILE3

    echo "$OPEN_PORT"
}

REPO="gitlab.morningconsult.com/mci/docker-credential-vault-login"
VAULT_VERSION="0.10.4"
VAULT_DEV_PORT=$(get_available_port)
VAULT_DEV_ROOT_TOKEN="31632a7e-ecca-ace5-feb0-4b7dfd22e04e"
ROOT=$(pwd)
TESTDATA="${ROOT}/testdata"
MACHINE=$(uname -m)
KERNEL=$(uname -s)

## Tests can only be run on 64-bit Linux machines
if [ "${KERNEL}" != "Linux" ] || [ "${MACHINE}" != "x86_64" ]; then
    echo "Tests may be run on a 64-bit Linux machine only. Exiting."
    exit 1
fi

## Make a testdata directory
mkdir -p $TESTDATA

## Make a temporary directory
TEMPDIR=$(mktemp -d vault.XXXXXX)
TEMPDIR="${ROOT}/${TEMPDIR}"

## Download Vault binary
wget --quiet -O $TEMPDIR/vault-${VAULT_VERSION}.zip https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip

## Unzip the Vault binary 
unzip -o $TEMPDIR/vault-${VAULT_VERSION}.zip -d $TEMPDIR

## Rename vault to vault-dev
mv $TEMPDIR/vault $TEMPDIR/vault-dev

## Start vault-dev in the background
$TEMPDIR/vault-dev server \
    -dev \
    -dev-listen-address="127.0.0.1:${VAULT_DEV_PORT}" \
    -dev-root-token-id="${VAULT_DEV_ROOT_TOKEN}" \
    -log-level=err &

sleep 2

## Run Go unit tests
printf "\n==> Starting Go unit tests...\n\n"
go test -v \
    -ldflags="-X ${REPO}/vault.VaultDevPortString=${VAULT_DEV_PORT} -X ${REPO}/vault.VaultDevRootToken=${VAULT_DEV_ROOT_TOKEN}" \
    -timeout 30s ./vault/...
printf "\n==> Tests complete\n\n"


## Kill vault-dev
pkill vault-dev 

## Delete the temporary directory
rm -rf $TEMPDIR
