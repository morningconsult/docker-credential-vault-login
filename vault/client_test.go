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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/config"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	server "github.com/hashicorp/vault/vault"
)

func TestClient(t *testing.T) {
	coreConfig := &server.CoreConfig{
		Logger: logging.NewVaultLogger(hclog.Error),
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}
	cluster := server.NewTestCluster(t, coreConfig, &server.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	server.TestWaitActive(t, core)
	client := cluster.Cores[0].Client

	// Mount the auth backend
	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
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

	// Give the approle permission to read the secret
	secretPath := "secret/docker/creds"
	policy := fmt.Sprintf(`path %q {
		capabilities = ["read", "list"]
	}`, secretPath)

	if err = client.Sys().PutPolicy("dev-policy", policy); err != nil {
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
	roleIDFile := filepath.Join("testdata", "test-approle-role-id")
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
	secretIDFile := filepath.Join("testdata", "test-approle-secret-id")
	defer os.Remove(secretIDFile)

	makeApproleFiles := func() {
		if err = ioutil.WriteFile(secretIDFile, []byte(secretID), 0644); err != nil {
			t.Fatal(err)
		}
		if err = ioutil.WriteFile(roleIDFile, []byte(roleID), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Enable the kv v2 secrets engine
	err = client.Sys().TuneMount("secret/", api.MountConfigInput{
		Options: map[string]string{"version": "2"},
	})
	if err != nil {
		t.Fatal("error tuning mount to kv v2")
	}

	cc := Client{
		client:      client,
		authTimeout: 3 * time.Minute,
		logger:      hclog.NewNullLogger(),
	}

	addr := client.Address()
	rootToken := client.Token()

	t.Run("GetCredentials/wrong-address", func(t *testing.T) {
		url := fmt.Sprintf("http://example.%s.com", randomUUID(t))
		client.SetAddress(url)
		defer client.SetAddress(addr)

		_, _, err := cc.GetCredentials(rootToken, "secret/doesnt/exist")
		if err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("GetCredentials/secret-doesnt-exist", func(t *testing.T) {
		_, _, err := cc.GetCredentials(rootToken, "secret/doesnt/exist")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `No secret found in Vault at path "secret/doesnt/exist"`
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("GetCredentials/no-username", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"password": "correct horse battery staple",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		_, _, err = cc.GetCredentials(rootToken, secret)
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := fmt.Sprintf(`No username found in Vault at path %q`, secret)
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("GetCredentials/no-password", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"username": "test@user.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		_, _, err = cc.GetCredentials(rootToken, secret)
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := fmt.Sprintf(`No password found in Vault at path %q`, secret)
		if err.Error() != expected {
			t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), expected))
		}
	})

	t.Run("GetCredentials/success-v1", func(t *testing.T) {
		secret := "secret/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"username": "test@user.com",
			"password": "correct horse battery staple",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		username, password, err := cc.GetCredentials(rootToken, secret)
		if err != nil {
			t.Fatal(err)
		}
		if username != "test@user.com" {
			t.Fatalf("Usernames differ:\n%v", cmp.Diff("test@user.com", username))
		}
		if password != "correct horse battery staple" {
			t.Fatalf("Errors differ:\n%v", cmp.Diff("correct horse battery staple", password))
		}
	})

	t.Run("GetCredentials/success-v2", func(t *testing.T) {
		secret := "secret/data/docker/creds"
		_, err := client.Logical().Write(secret, map[string]interface{}{
			"data": map[string]interface{}{
				"username": "test@user.com",
				"password": "correct horse battery staple",
			},
			"metadata": map[string]interface{}{
				"created_time":  "2019-10-24T18:39:39.656654Z",
				"deletion_time": "",
				"destroyed":     false,
				"version":       "1",
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Logical().Delete(secret)

		username, password, err := cc.GetCredentials(rootToken, secret)
		if err != nil {
			t.Fatal(err)
		}
		if username != "test@user.com" {
			t.Fatalf("Usernames differ:\n%v", cmp.Diff("test@user.com", username))
		}
		if password != "correct horse battery staple" {
			t.Fatalf("Errors differ:\n%v", cmp.Diff("correct horse battery staple", password))
		}
	})

	t.Run("Authenticate/error-building-auth", func(t *testing.T) {
		cc := Client{
			logger: hclog.NewNullLogger(),
			authConfig: &config.AutoAuth{
				Method: &config.Method{Type: "magic"}, // Method not supported
			},
		}

		_, err := cc.Authenticate(context.Background())
		if err == nil {
			t.Fatal("Expected an error")
		}
		gotErr := err.Error()
		expectErr := "error creating auth method: unknown auth method \"magic\""
		if gotErr != expectErr {
			t.Errorf("Expected error:\n%s\nGot error:\n%s", expectErr, gotErr)
		}
	})

	t.Run("Authenticate/timeout", func(t *testing.T) {
		cc := Client{
			client: client,
			logger: hclog.NewNullLogger(),
			authConfig: &config.AutoAuth{
				Method: &config.Method{
					Type:      "approle",
					MountPath: "auth/approle",
					Config: map[string]interface{}{
						"secret":              secretPath,
						"role_id_file_path":   roleIDFile,
						"secret_id_file_path": secretIDFile,
					},
				},
			},
			authTimeout: 1 * time.Millisecond,
		}

		_, err := cc.Authenticate(context.Background())
		if err == nil {
			t.Fatal("Expected an error")
		}
		gotErr := err.Error()
		expectErr := "failed to get credentials within timeout (1ms)"
		if gotErr != expectErr {
			t.Errorf("Expected error:\n%s\nGot error:\n%s", expectErr, gotErr)
		}
	})

	t.Run("Authenticate/success", func(t *testing.T) {
		makeApproleFiles()

		cc := Client{
			client: client,
			logger: hclog.NewNullLogger(),
			authConfig: &config.AutoAuth{
				Method: &config.Method{
					Type:      "approle",
					MountPath: "auth/approle",
					Config: map[string]interface{}{
						"secret":              secretPath,
						"role_id_file_path":   roleIDFile,
						"secret_id_file_path": secretIDFile,
					},
				},
			},
			authTimeout: 30 * time.Second,
		}

		_, err := cc.Authenticate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CacheToken/error-building-sinks", func(t *testing.T) {
		buf := bytes.Buffer{}
		logger := hclog.New(&hclog.LoggerOptions{Output: &buf})
		cc := Client{
			client: client,
			logger: logger,
			authConfig: &config.AutoAuth{
				Sinks: []*config.Sink{
					{Type: "kitchen"},
				},
			},
			authTimeout: 30 * time.Second,
		}

		cc.CacheToken(context.Background(), "")
		if !strings.Contains(buf.String(), `[ERROR] error building sinks; will not cache token: error="unknown sink type "kitchen""`) {
			t.Errorf("unexpected error:\n%s", buf.String())
		}
	})

	t.Run("CacheToken/success", func(t *testing.T) {
		tokenFile := "testdata/my-token"
		defer os.Remove(tokenFile)

		cc := Client{
			client: client,
			logger: hclog.NewNullLogger(),
			authConfig: &config.AutoAuth{
				Sinks: []*config.Sink{
					{
						Type: "file",
						Config: map[string]interface{}{
							"path": tokenFile,
						},
					},
				},
			},
			authTimeout: 30 * time.Second,
		}

		token := "19c6107c-5509-42d4-883f-5a8ae7ed5e07"

		cc.CacheToken(context.Background(), token)

		if _, err := os.Stat(tokenFile); err != nil {
			t.Fatalf("Did not cache token")
		}

		gotToken, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			t.Fatal(err)
		}

		if string(gotToken) != token {
			t.Errorf("Expected token %q, got token %q", token, gotToken)
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
