#!/usr/bin/env bash

ORIGIN=$(pwd)
GITLAB="gitlab.morningconsult.com/mci"

## Make a temporary directory
TEMPDIR=$(mktemp -d get-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${TEMPDIR}"
export PATH="${GOPATH}/bin:${PATH}"
cd $TEMPDIR

## Get repo
mkdir -p "src/${GITLAB}"
cd "src/${GITLAB}"
echo "Fetching ${GITLAB}/docker-credential-vault-login..."
git clone git@gitlab.morningconsult.com:mci/docker-credential-vault-login
cd docker-credential-vault-login

## Get govendor
go get -u github.com/kardianos/govendor

govendor init

govendor remove +unused

## Fetch dependencies
echo "Fetching dependencies. This will take some time..."
govendor fetch +missing

## Move vendor files to the original project folder
cp -R vendor/* "${ORIGIN}/vendor"

## Delete the temporary directory
cd $ORIGIN
rm -rf $TEMPDIR
