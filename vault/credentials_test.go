// Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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

package vault

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	server "github.com/hashicorp/vault/vault"
)

func TestGetCredentials(t *testing.T) {
	coreConfig := &server.CoreConfig{
		Logger: logging.NewVaultLogger(hclog.Error),
	}
	cluster := server.NewTestCluster(t, coreConfig, &server.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	server.TestWaitActive(t, core)
	client := cluster.Cores[0].Client
	addr := client.Address()

	t.Run("wrong-address", func(t *testing.T) {
		url := fmt.Sprintf("http://example.%s.com", randomUUID(t))
		client.SetAddress(url)
		defer client.SetAddress(addr)

		_, err := GetCredentials("secret/doesnt/exist", client)
		if err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("secret-doesnt-exist", func(t *testing.T) {
		_, err := GetCredentials("secret/doesnt/exist", client)
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `No secret found in Vault at path "secret/doesnt/exist"`
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("no-username", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"password": "correct horse battery staple",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		_, err = GetCredentials(secret, client)
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := fmt.Sprintf(`No username found in Vault at path %q`, secret)
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("no-password", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"username": "test@user.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		_, err = GetCredentials(secret, client)
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := fmt.Sprintf(`No password found in Vault at path %q`, secret)
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("success", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"username": "test@user.com",
			"password": "correct horse battery staple",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		creds, err := GetCredentials(secret, client)
		if err != nil {
			t.Fatal(err)
		}
		if creds.Username != "test@user.com" {
			t.Fatalf("Usernames differ:\n%v", cmp.Diff("test@user.com", creds.Username))
		}
		if creds.Password != "correct horse battery staple" {
			t.Fatalf("Errors differ:\n%v", cmp.Diff("correct horse battery staple", creds.Password))
		}
	})
}

func randomUUID(t *testing.T) string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
