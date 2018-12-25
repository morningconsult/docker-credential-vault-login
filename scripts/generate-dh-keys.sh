#!/bin/bash

set -e 

if [ -z $( which go ) ]
then
	echo "Go is not installed. Please install Go before running this script."
fi

ROOT=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )
TEMPDIR="${ROOT}/$( mktemp -d generate-dh-keys.XXXXXX )"

export GOPATH="${TEMPDIR}"

cd $GOPATH

go get github.com/hashicorp/vault/helper/dhutil

cat <<EOF > main.go
package main

import (
	"encoding/base64"
	"io/ioutil"
	"encoding/json"
	"log"

	"github.com/hashicorp/vault/helper/dhutil"
)

const dhpath = "/tmp/test/file-foo-dhpath"

type PrivateKeyInfo struct {
	Curve25519PrivateKey string \`json:"curve25519_private_key"\`
}

func main() {
	pub, pri, err := dhutil.GeneratePublicPrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	mPubKey, err := json.Marshal(&dhutil.PublicKeyInfo{
		Curve25519PublicKey: pub,
	})
	if err != nil {
		log.Fatal(err)
	}

	mPrivKey, err := json.Marshal(&PrivateKeyInfo{
		Curve25519PrivateKey: base64.StdEncoding.EncodeToString(pri),
	})
	if err != nil {
		log.Fatal(err)
	}


	if err := ioutil.WriteFile("dh-pub-key.json", mPubKey, 0644); err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile("dh-priv-key.json", mPrivKey, 0644); err != nil {
		log.Fatal(err)
	}
}
EOF

go run main.go

cp dh-*-key.json "${ROOT}"

cd $ROOT

rm -rf $TEMPDIR

echo "Done. The following Diffie-Hellman keys were created:"

find . -name "dh-*-key.json" | grep -v "testdata"