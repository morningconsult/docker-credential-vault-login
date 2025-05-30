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
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
)

func TestBuildSinks(t *testing.T) {
	logger := hclog.NewNullLogger()
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		configs []*config.Sink
		err     string
	}{
		{
			"bad-type",
			[]*config.Sink{
				{
					Type: "kitchen",
				},
			},
			`unknown sink type "kitchen"`,
		},
		{
			"new-file-sink-error",
			[]*config.Sink{
				{
					Type: "file",
					Config: map[string]interface{}{
						"no": "path!",
					},
				},
			},
			"error creating file sink: 'path' not specified for file sink",
		},
		{
			"success",
			[]*config.Sink{
				{
					Type: "file",
					Config: map[string]interface{}{
						"path": "testdata/test-sink",
					},
				},
			},
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildSinks(tc.configs, logger, client)
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
		})
	}
}

func TestBuildAuthMethod(t *testing.T) {
	logger := hclog.NewNullLogger()
	cases := []struct {
		name   string
		config *config.Method
		err    string
	}{
		{
			"aws",
			&config.Method{
				Type: "aws",
				Config: map[string]interface{}{
					"type": "ec2",
					"role": "dev-role",
				},
			},
			"",
		},
		{
			"azure",
			&config.Method{
				Type: "azure",
				Config: map[string]interface{}{
					"role":     "dev-test",
					"resource": "important-stuff",
				},
			},
			"",
		},
		{
			"cert",
			&config.Method{
				Type:   "cert",
				Config: map[string]interface{}{},
			},
			"",
		},
		{
			"cf",
			&config.Method{
				Type: "cf",
				Config: map[string]interface{}{
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"gcp",
			&config.Method{
				Type: "gcp",
				Config: map[string]interface{}{
					"type": "gce",
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"jwt",
			&config.Method{
				Type: "jwt",
				Config: map[string]interface{}{
					"path": "jwt/token",
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"kubernetes",
			&config.Method{
				Type: "kubernetes",
				Config: map[string]interface{}{
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"approle",
			&config.Method{
				Type: "approle",
				Config: map[string]interface{}{
					"role_id_file_path":   "path/to/role/id",
					"secret_id_file_path": "path/to/secret/id",
				},
			},
			"",
		},
		{
			"unknown",
			&config.Method{
				Type:   "fingerprint",
				Config: map[string]interface{}{},
			},
			`unknown auth method "fingerprint"`,
		},
		{
			"error",
			&config.Method{
				Type:   "alicloud",
				Config: map[string]interface{}{},
			},
			"error creating alicloud auth method: 'role' is required but is not provided",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildAuthMethod(tc.config, logger)
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
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	oldEnv := stashEnv()
	defer popEnv(oldEnv)

	testToken := randomUUID(t)

	cases := []struct {
		name   string
		env    map[string]string
		method *config.Method
		vault  *config.Vault
		err    string
		post   func(*api.Client)
	}{
		{
			name: "env-precedence",
			env: map[string]string{
				api.EnvVaultAddress: "http://example.com",
			},
			method: &config.Method{Type: "aws"},
			vault:  &config.Vault{Address: "http://127.0.0.1:8201"},
			err:    "",
			post: func(c *api.Client) {
				if c.Address() != "http://example.com" {
					t.Errorf("Expected Vault address %s, got %s", "http://example.com", c.Address())
				}
			},
		},
		{
			name:   "config-in-no-env-counterpart",
			env:    map[string]string{},
			method: &config.Method{Type: "aws"},
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
			name:   "clears-token-if-not-token-auth",
			env:    map[string]string{},
			method: &config.Method{Type: "aws"},
			vault:  &config.Vault{},
			err:    "",
			post: func(c *api.Client) {
				if c.Token() != "" {
					t.Errorf("Expected client to have no token but it has one")
				}
			},
		},
		{
			name: "sets-token-from-env-if-token-auth",
			env: map[string]string{
				api.EnvVaultToken: testToken,
			},
			method: &config.Method{Type: "token"},
			vault:  &config.Vault{},
			err:    "",
			post: func(c *api.Client) {
				if c.Token() != testToken {
					t.Errorf("Expected client to have token %s but it has %s", testToken, c.Token())
				}
			},
		},
		{
			name: "sets-token-from-config-if-not-set-in-env-and-token-auth",
			env:  map[string]string{},
			method: &config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": testToken,
				},
			},
			vault: &config.Vault{},
			err:   "",
			post: func(c *api.Client) {
				if c.Token() != testToken {
					t.Errorf("Expected client to have token %s but it has %s", testToken, c.Token())
				}
			},
		},
		{
			name: "no-token",
			env:  map[string]string{},
			method: &config.Method{
				Type:   "token",
				Config: map[string]interface{}{}, // no token in config
			},
			vault: &config.Vault{},
			err:   "missing 'auto_auth.method.config.token' value",
			post:  func(*api.Client) {},
		},
		{
			name: "token-not-string",
			env:  map[string]string{},
			method: &config.Method{
				Type:   "token",
				Config: map[string]interface{}{"token": 1234}, // no token in config
			},
			vault: &config.Vault{},
			err:   "could not convert 'auto_auth.method.config.token' config value to string",
			post:  func(*api.Client) {},
		},
		{
			name: "token-is-empty",
			env:  map[string]string{},
			method: &config.Method{
				Type:   "token",
				Config: map[string]interface{}{"token": ""},
			},
			vault: &config.Vault{},
			err:   "'auto_auth.method.config.token' value is empty",
			post:  func(*api.Client) {},
		},
		{
			name: "new-client-error",
			env: map[string]string{
				api.EnvRateLimit: "asdf",
			},
			method: &config.Method{},
			vault:  &config.Vault{},
			err:    "VAULT_RATE_LIMIT was provided but incorrectly formatted",
			post:   func(*api.Client) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for env, val := range tc.env {
				t.Setenv(env, val)
			}

			client, err := NewClient(tc.method, tc.vault)
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
