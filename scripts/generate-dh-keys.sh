#!/bin/sh
# Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#         https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

set -e 

ROOT=$( cd "$( dirname "${0}" )/.." && pwd )
TEMPDIR="${ROOT}/$( mktemp -d generate-dh-keys.XXXXXX )"

cd "${TEMPDIR}"

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

GO111MODULE=on go run main.go

cp dh-*-key.json "${ROOT}"

cd "${ROOT}"

rm -rf "${TEMPDIR}"

echo "Done. The following Diffie-Hellman keys were created:"

find . -name "dh-*-key.json" | grep -v "testdata"
