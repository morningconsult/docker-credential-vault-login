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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/config"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"

	mciconfig "github.com/morningconsult/docker-credential-vault-login/config"
	"github.com/morningconsult/docker-credential-vault-login/helper"
	mcivault "github.com/morningconsult/docker-credential-vault-login/vault"
)

func TestNewLogWriter(t *testing.T) {
	noop := func() {}
	cases := []struct {
		name   string
		pre    func()
		config map[string]interface{}
		err    string
		post   func()
	}{
		{
			name: "log-dir-from-env",
			pre: func() {
				os.Setenv(envLogDir, "testdata")
			},
			err: "",
			post: func() {
				os.Unsetenv(envLogDir)
			},
		},
		{
			name: "log-dir-from-config",
			pre: func() {
				os.Unsetenv(envLogDir)
			},
			config: map[string]interface{}{"log_dir": "testdata"},
			err:    "",
			post:   noop,
		},
		{
			name:   "error-expanding-log-dir",
			pre:    noop,
			config: map[string]interface{}{"log_dir": "~asdgweq"},
			err:    "error expanding logging directory : cannot expand user-specific home dir",
			post:   noop,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.pre()
			defer tc.post()

			file, err := newLogWriter(tc.config)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Results differ:\n%v", cmp.Diff(err.Error(), tc.err))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			file.Close()
			filename := file.Name()
			if _, err = os.Stat(filename); err != nil {
				t.Fatal(err)
			}
			os.Remove(filename)
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	oldEnv := stashEnv()
	defer popEnv(oldEnv)

	cases := []struct {
		name  string
		env   map[string]string
		vault *config.Vault
		err   string
		post  func(*api.Client)
	}{
		{
			name: "env-precedence",
			env: map[string]string{
				api.EnvVaultAddress: "http://example.com",
			},
			vault: &config.Vault{Address: "http://127.0.0.1:8201"},
			err:   "",
			post: func(c *api.Client) {
				if c.Address() != "http://example.com" {
					t.Errorf("Expected Vault address %s, got %s", "http://example.com", c.Address())
				}
			},
		},
		{
			name: "config-in-no-env-counterpart",
			env:  map[string]string{},
			vault: &config.Vault{
				Address:          "http://example.com",
				TLSSkipVerifyRaw: "true",
			},
			err: "",
			post: func(c *api.Client) {
				if c.Address() != "http://example.com" {
					t.Errorf("Expected Vault address %s, got %s", "http://example.com", c.Address())
				}
			},
		},
		{
			name: "new-client-error",
			env: map[string]string{
				api.EnvRateLimit: "asdf",
			},
			vault: &config.Vault{},
			err:   "VAULT_RATE_LIMIT was provided but incorrectly formatted",
			post:  func(*api.Client) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for env, new := range tc.env {
				old := os.Getenv(env)
				defer os.Setenv(env, old)
				os.Setenv(env, new)
			}

			client, err := newVaultClient(tc.vault)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Errors differ:\n%v", cmp.Diff(tc.err, err.Error()))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.post(client)
		})
	}
}

func TestGetToken(t *testing.T) {
	cases := []struct {
		name        string
		method      *config.Method
		expectErr   string
		expectToken string
	}{
		{
			"success",
			&config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": "4f13d9dc-2460-45fd-a702-f2ec51db7e6f",
				},
			},
			"",
			"4f13d9dc-2460-45fd-a702-f2ec51db7e6f",
		},
		{
			"no-token",
			&config.Method{
				Type:   "token",
				Config: map[string]interface{}{},
			},
			"missing 'auto_auth.method.config.token' value",
			"",
		},
		{
			"token-not-string",
			&config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": 12345,
				},
			},
			"could not convert 'auto_auth.method.config.token' config value to string",
			"",
		},
		{
			"token-empty",
			&config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": "",
				},
			},
			"'auto_auth.method.config.token' value is empty",
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotToken, err := getToken(tc.method)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("Expected an error")
				}
				gotErr := err.Error()
				if gotErr != tc.expectErr {
					t.Fatalf("Expected error:\n%s\nGot error:\n%s", tc.expectErr, gotErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotToken != tc.expectToken {
				t.Errorf("Expected token %s, got token %s", tc.expectToken, gotToken)
			}
		})
	}
}

func TestHelper_EndToEnd(t *testing.T) {
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
	// rootToken := client.Token()

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

	// Create the configuration file
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
		wrap_ttl = "5m"
		aad      = "TESTAAD"
		dh_type  = "curve25519"
		dh_path  = "testdata/dh-pub-key.json"
		config   = {
			path    = "testdata/token-sink"
			dh_priv = "testdata/dh-priv-key.json"
		}
	}
}`
	hcl = fmt.Sprintf(hcl, secretPath, roleIDFile, secretIDFile)

	configFile := filepath.Join("testdata", "testing.hcl")
	if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile)
	defer os.Remove(filepath.Join("testdata", "token-sink"))

	// Load configuration from file
	config, err := mciconfig.LoadConfig(configFile)
	if err != nil {
		t.Fatal(err)
	}

	// Build secrets table
	secretsTable, err := mciconfig.BuildSecretsTable(config.AutoAuth.Method.Config)
	if err != nil {
		t.Fatalf("error building secrets table: %v", err)
	}

	client.ClearToken()

	mciClient := mcivault.NewClient(mcivault.ClientOptions{
		Logger:     hclog.NewNullLogger(),
		Client:     client,
		AuthConfig: config.AutoAuth,
	})

	h := helper.New(helper.Options{
		Logger:      hclog.NewNullLogger(),
		Client:      mciClient,
		Secret:      secretsTable,
		EnableCache: true,
	})

	username, password, err := h.Get("")
	if err != nil {
		t.Fatal(err)
	}

	if username != "test@user.com" {
		t.Errorf("Expected username %q, got %q", "test@user.com", username)
	}

	if password != "secure password" {
		t.Errorf("Expected password %q, got %q", "secure password", password)
	}
}

func stashEnv() []string {
	env := os.Environ()
	os.Clearenv()
	return env
}

func popEnv(env []string) {
	os.Clearenv()

	for _, e := range env {
		p := strings.SplitN(e, "=", 2)
		k, v := p[0], ""
		if len(p) > 1 {
			v = p[1]
		}
		os.Setenv(k, v)
	}
}
