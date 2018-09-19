#!/usr/bin/env bash

# ORIGIN=$(pwd)
ORG="github.com/morningconsult"
TOOL="docker-credential-vault-login"

## Make a temporary directory
TEMPDIR=$(mktemp -d get-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${TEMPDIR}"
export PATH="${GOPATH}/bin:${PATH}"
cd $TEMPDIR

## Get repo
mkdir -p "src/${ORG}"
cd "src/${ORG}"
echo "Fetching ${TOOL}..."
git clone git@github.com:morningconsult/${TOOL}
cd ${TOOL}

## Clean out earlier vendoring
rm -rf Godeps vendor

## Get govendor
go get -u github.com/kardianos/govendor

govendor init

## Fetch dependencies
echo "Fetching dependencies. This will take some time..."
govendor add +external

printf "Done; to commit, run: \n\n    $ cd ${GOPATH}/src/${ORG}/${TOOL}\n\n"