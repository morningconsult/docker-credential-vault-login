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

package helper

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/config"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func TestHelper_Add(t *testing.T) {
	h := New(Options{})
	err := h.Add(&credentials.Credentials{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_Delete(t *testing.T) {
	h := New(Options{})
	err := h.Delete("")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_List(t *testing.T) {
	h := New(Options{})
	_, err := h.List()
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_Get(t *testing.T) {
	// Note: This is an end-to-end test using the approle authentication method
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	coreConfig := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(hclog.Error),
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client
	rootToken := client.Token()

	// Mount the auth backend
	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Tune the mount
	err = client.Sys().TuneMount("auth/approle", api.MountConfigInput{
		DefaultLeaseTTL: "20s",
		MaxLeaseTTL:     "20s",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create role
	_, err = client.Logical().Write("auth/approle/role/role-period", map[string]interface{}{
		"period":   "20s",
		"policies": "dev-policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get role_id
	resp, err := client.Logical().Read("auth/approle/role/role-period/role-id")
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the role-id")
	}
	roleID, ok := resp.Data["role_id"].(string)
	if !ok {
		t.Fatal("could not convert 'role_id' to string")
	}
	roleIDFile := filepath.Join(testdata, "test-approle-role-id")
	defer os.Remove(roleIDFile)

	// Get secret_id
	resp, err = client.Logical().Write("auth/approle/role/role-period/secret-id", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the secret-id")
	}
	secretID, ok := resp.Data["secret_id"].(string)
	if !ok {
		t.Fatal("could not convert 'secret_id' to string")
	}
	secretIDFile := filepath.Join(testdata, "test-approle-secret-id")
	defer os.Remove(secretIDFile)

	makeApproleFiles := func() {
		if err = ioutil.WriteFile(secretIDFile, []byte(secretID), 0644); err != nil {
			t.Fatal(err)
		}
		if err = ioutil.WriteFile(roleIDFile, []byte(roleID), 0644); err != nil {
			t.Fatal(err)
		}
	}

	makeApproleFiles()

	// Write a secret
	secretPath := "secret/docker/creds"
	_, err = client.Logical().Write(secretPath, map[string]interface{}{
		"username": "test@user.com",
		"password": "secure password",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Give the approle permission to read the secret
	policy := fmt.Sprintf(`path %q {
	capabilities = ["read", "list"]
}`, secretPath)
	if err = client.Sys().PutPolicy("dev-policy", policy); err != nil {
		t.Fatal(err)
	}

	hcl := `
auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			secret              = %q
			role_id_file_path   = %q
			secret_id_file_path = %q
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
	hcl = fmt.Sprintf(hcl, secretPath, roleIDFile, secretIDFile)

	configFile := filepath.Join(testdata, "testing.hcl")
	if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile)
	defer os.Remove("testdata/token-sink")

	config, err := config.LoadConfig(configFile, hclog.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}

	client.ClearToken()
	h := New(Options{
		Logger:      hclog.NewNullLogger(),
		Client:      client,
		AuthTimeout: 3,
		Secret:      secretPath,
		AuthConfig:  config.AutoAuth,
		EnableCache: true,
	})

	// Test that it can read authenticate, get a new token, and read the secret
	user, pw, err := h.Get("")
	if err != nil {
		t.Fatal(err)
	}

	if user != "test@user.com" {
		t.Fatalf("Got username %q, expected \"test@user.com\"", user)
	}
	if pw != "secure password" {
		t.Fatalf("Got password %q, expected \"secure password\"", pw)
	}

	if _, err = os.Stat("testdata/token-sink"); err != nil {
		t.Fatal(err)
	}

	data, err := ioutil.ReadFile("testdata/token-sink")
	if err != nil {
		t.Fatal(err)
	}
	clientToken := string(data)

	// Test that it can read the secret using the cached token
	t.Run("can-use-cached-token", func(t *testing.T) {
		h.client.ClearToken()
		h.cacheEnabled = true

		makeApproleFiles()

		user, pw, err = h.Get("")
		if err != nil {
			t.Fatal(err)
		}

		if user != "test@user.com" {
			t.Errorf("Got username %q, expected \"test@user.com\"", user)
		}
		if pw != "secure password" {
			t.Errorf("Got password %q, expected \"secure password\"", pw)
		}
		if h.client.Token() != clientToken {
			t.Errorf("Expected token %s, got token %s", clientToken, h.client.Token())
		}
	})

	// Test that caching can be disabled by setting the environment
	// variable
	t.Run("can-disable-caching", func(t *testing.T) {
		h.client.ClearToken()
		h.cacheEnabled = false

		makeApproleFiles()

		os.Remove("testdata/token-sink")
		user, pw, err = h.Get("")
		if err != nil {
			t.Fatal(err)
		}

		if user != "test@user.com" {
			t.Fatalf("Got username %q, expected \"test@user.com\"", user)
		}
		if pw != "secure password" {
			t.Fatalf("Got password %q, expected \"secure password\"", pw)
		}
		if _, err = os.Stat("testdata/token-sink"); !os.IsNotExist(err) {
			t.Fatal("helper.Get() should not have cached a token")
		}
	})

	// Ensure that if the client attempts to read the secret with
	// a bad token it fails
	t.Run("fails-when-bad-token-used", func(t *testing.T) {
		h.client.SetToken("bad token!")
		buf := bytes.Buffer{}
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: &buf,
		})

		makeApproleFiles()

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error when client attempts to read secret with a bad token")
		}
		expected := fmt.Sprintf(`[ERROR] error reading secret from Vault: error="error reading secret: Error making API request.

URL: GET %s/v1/%s
Code: 403. Errors:

* permission denied"`, h.client.Address(), secretPath)
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("\nExpected error to contain:\n\t%s\nReceived the following error(s):\n\t%s",
				expected, buf.String())
		}
	})

	// Ensure that if the role does not have permission to read
	// the secret, it fails
	t.Run("fails-when-no-policy", func(t *testing.T) {
		client.SetToken(rootToken)
		buf := bytes.Buffer{}
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: &buf,
			Level:  hclog.Error,
		})

		// Delete the policy that allows the app role to read the secret
		if err = client.Sys().DeletePolicy("dev-policy"); err != nil {
			t.Fatal(err)
		}

		// Set to non-root token
		h.client.SetToken(clientToken)

		makeApproleFiles()

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error when role attempts to read secret with without permission")
		}

		expected := fmt.Sprintf(`[ERROR] error reading secret from Vault: error="error reading secret: Error making API request.

URL: GET %s/v1/%s
Code: 403. Errors:

* 1 error occurred:
	* permission denied`, h.client.Address(), secretPath)
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("\nExpected error to contain:\n\t%s\nReceived the following error(s):\n\t%s",
				expected, buf.String())
		}
	})

}

func TestHelper_Get_FastTimeout(t *testing.T) {

	buf := bytes.Buffer{}
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Error,
		Output: &buf,
	})
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.SetMaxRetries(1)
	client.SetClientTimeout(1 * time.Second)
	client.ClearToken()

	config, err := config.LoadConfig("testdata/valid.hcl", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{
		Secret:      "secret/docker/creds",
		Logger:      logger,
		AuthTimeout: 1,
		Client:      client,
		AuthConfig:  config.AutoAuth,
	})
	_, _, err = h.Get("")
	if err == nil {
		t.Fatal("expected an error")
	}

	expected := `failed to get credentials within timeout (1s)`
	if !strings.Contains(buf.String(), expected) {
		t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
	}
}
