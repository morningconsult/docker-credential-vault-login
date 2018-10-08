// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//         https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package auth

import (
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
	"testing"
)

func TestGetCredentials(t *testing.T) {
	var (
		username = "frodo.baggins@theshire.com"
		password = "potatoes"
	)

	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := NewDefaultClient(test.NewPreConfiguredVaultClient(t, cluster))

	cases := []struct {
		name        string
		actualPath  string
		requestPath string
		secret      map[string]interface{}
		err         bool
	}{
		{
			"success",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"username": username,
				"password": password,
			},
			false,
		},
		{
			"wrong-path",
			"secret/foo/bar",
			"secret/bim/baz",
			map[string]interface{}{
				"username": username,
				"password": password,
			},
			true,
		},
		{
			"no-username",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"password": password,
			},
			true,
		},
		{
			"no-password",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"username": username,
			},
			true,
		},
		{
			"no-creds",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"user": username,
				"pw":   password,
			},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.WriteSecret(t, client.(*DefaultClient).RawClient(), tc.actualPath, tc.secret)

			creds, err := client.GetCredentials(tc.requestPath)

			if tc.err {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				return
			}

			if creds.Username != username {
				t.Fatalf("Unexpected username (expected %q, got %q)", username, creds.Username)
			}
			if creds.Password != password {
				t.Fatalf("Unexpected password (expected %q, got %q)", password, creds.Password)
			}
		})
	}
}
