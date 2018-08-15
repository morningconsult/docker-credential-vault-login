#!/usr/bin/env bash

# ORIGIN=$(pwd)
GITLAB="gitlab.morningconsult.com/mci"
TOOL="docker-credential-vault-login"

## Make a temporary directory
TEMPDIR=$(mktemp -d get-deps.XXXXXX)

## Set paths
export GOPATH="$(pwd)/${TEMPDIR}"
export PATH="${GOPATH}/bin:${PATH}"
cd $TEMPDIR

## Get repo
mkdir -p "src/${GITLAB}"
cd "src/${GITLAB}"
echo "Fetching ${TOOL}..."
git clone git@gitlab.morningconsult.com:mci/${TOOL}
cd ${TOOL}

## Clean out earlier vendoring
rm -rf Godeps vendor

## Get govendor
go get -u github.com/kardianos/govendor

govendor init

## Fetch dependencies
echo "Fetching dependencies. This will take some time..."
govendor fetch +missing

printf "Done; to commit, run: \n\n    $ cd ${GOPATH}/src/${GITLAB}/${TOOL}\n\n"