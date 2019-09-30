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

package config

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	vaultconfig "github.com/hashicorp/vault/command/agent/config"
)

func TestLoadConfig(t *testing.T) {

	cases := []struct {
		name         string
		file         string
		err          string
		expectConfig *vaultconfig.Config
	}{
		{
			"file-doesnt-exist",
			"testdata/nonexistent.hcl",
			"stat testdata/nonexistent.hcl: no such file or directory",
			nil,
		},
		{
			"provided-directory",
			"testdata",
			"location is a directory, not a file",
			nil,
		},
		{
			"empty-file",
			"testdata/empty-file.hcl",
			"no 'auto_auth' block found in configuration file",
			nil,
		},
		{
			"no-method",
			"testdata/no-method.hcl",
			"error parsing 'auto_auth': error parsing 'method': one and only one \"method\" block is required",
			nil,
		},
		{
			"multiple-sinks",
			"testdata/multiple-sinks.hcl",
			"",
		},
		{
			"no-sinks",
			"testdata/no-sinks.hcl",
			"",
			&vaultconfig.Config{
				AutoAuth: &vaultconfig.AutoAuth{
					Method: &vaultconfig.Method{
						Type:      "approle",
						MountPath: "auth/approle",
						Config: map[string]interface{}{
							"role_id_file_path":   "/tmp/role-id",
							"secret":              "secret/docker/creds",
							"secret_id_file_path": "/tmp/secret-id",
						},
					},
				},
			},
		},
		{
			"no-mount-path",
			"testdata/no-mount-path.hcl",
			"",
			&vaultconfig.Config{
				AutoAuth: &vaultconfig.AutoAuth{
					Method: &vaultconfig.Method{
						Type:      "aws",
						MountPath: "auth/aws",
						Config: map[string]interface{}{
							"role":   "dev-role-iam",
							"secret": "secret/docker/creds",
							"type":   "iam",
						},
					},
					Sinks: []*vaultconfig.Sink{
						{
							Type: "file",
							Config: map[string]interface{}{
								"path": "/tmp/foo",
							},
						},
					},
				},
			},
		},
		{
			"valid",
			"testdata/valid.hcl",
			"",
			&vaultconfig.Config{
				AutoAuth: &vaultconfig.AutoAuth{
					Method: &vaultconfig.Method{
						Type:      "approle",
						MountPath: "auth/approle",
						Config: map[string]interface{}{
							"role_id_file_path":   "/tmp/role-id",
							"secret":              "secret/docker/creds",
							"secret_id_file_path": "/tmp/secret-id",
						},
					},
					Sinks: []*vaultconfig.Sink{
						{
							Type: "file",
							Config: map[string]interface{}{
								"path": "/tmp/foo",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotConfig, err := LoadConfig(tc.file)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Expected error:\n\t%s\nGot:\n\t%s", tc.err, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			comparer := cmp.Comparer(func(c1 *vaultconfig.Config, c2 *vaultconfig.Config) bool {
				if (c1 == nil || c2 == nil) && !((c1 == nil) && (c2 == nil)) {
					return false
				}
				return cmp.Equal(c1.AutoAuth, c2.AutoAuth) && cmp.Equal(c1.Vault, c2.Vault)
			})
			if !cmp.Equal(tc.expectConfig, gotConfig, comparer) {
				t.Errorf("Configurations differ:\n%v", cmp.Diff(tc.expectConfig, gotConfig))
			}
		})
	}
}

func TestBuildSecretsTable(t *testing.T) {
	cases := []struct {
		name               string
		config             map[string]interface{}
		expectErr          string
		expectSecretsTable SecretsTable
	}{
		{
			name:               "no-secrets-field",
			config:             map[string]interface{}{},
			expectErr:          "path to the secret where your Docker credentials are stored must be specified via in the field 'auto_auth.method.config.secret' of the config file", // nolint: lll
			expectSecretsTable: SecretsTable{},
		},
		{
			name: "empty-string-secret",
			config: map[string]interface{}{
				"secret": "",
			},
			expectErr:          "field 'auto_auth.method.config.secret' is empty",
			expectSecretsTable: SecretsTable{},
		},
		{
			name: "valid-string-secret",
			config: map[string]interface{}{
				"secret": "secret/docker/creds",
			},
			expectErr:          "",
			expectSecretsTable: SecretsTable{oneSecret: "secret/docker/creds"},
		},
		{
			name: "empty-map-secrets",
			config: map[string]interface{}{
				"secret": map[string]interface{}{},
			},
			expectErr:          "field 'auto_auth.method.config.secret' must be either a string or a map",
			expectSecretsTable: SecretsTable{},
		},
		{
			name: "map-secrets-have-empty-values",
			config: map[string]interface{}{
				"secret": map[string]interface{}{
					"registry.example.com": "",
				},
			},
			expectErr:          "field 'auto_auth.method.config.secret' must be either a string or a map",
			expectSecretsTable: SecretsTable{},
		},
		{
			name: "valid-map-secrets",
			config: map[string]interface{}{
				"secret": map[string]interface{}{
					"registry.example.com": "secret/docker/creds",
				},
			},
			expectErr: "field 'auto_auth.method.config.secret' must be either a string or a map",
			expectSecretsTable: SecretsTable{
				registryToSecret: map[string]string{
					"registry.example.com": "secret/docker/creds",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := BuildSecretsTable(tc.config)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				gotErr := err.Error()
				if gotErr != tc.expectErr {
					t.Fatalf("Expected error %q, got error %q", tc.expectErr, gotErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tc.expectSecretsTable, st) {
				t.Errorf("Expected:\n%+v\nGot:\n%v", tc.expectSecretsTable, st)
			}
		})
	}
}

func TestEndToEnd(t *testing.T) {
	t.Run("one-secret", func(t *testing.T) {
		cfg, err := LoadConfig("testdata/valid.hcl")
		if err != nil {
			t.Fatal(err)
		}
		secretTable, err := BuildSecretsTable(cfg.AutoAuth.Method.Config)
		if err != nil {
			t.Fatal(err)
		}
		expectSecret := "secret/docker/creds"
		expectST := SecretsTable{oneSecret: expectSecret}
		if !reflect.DeepEqual(expectST, secretTable) {
			t.Fatalf("Expected secrets table %+v, got secrets table %+v", expectST, secretTable)
		}
		gotSecret := expectST.GetPath("")
		if expectSecret != gotSecret {
			t.Errorf("Secrets differ:\n%v", cmp.Diff(expectSecret, gotSecret))
		}
	})

	t.Run("multiple-secrets", func(t *testing.T) {
		cfg, err := LoadConfig("testdata/multi-secret.hcl")
		if err != nil {
			t.Fatal(err)
		}
		secretTable, err := BuildSecretsTable(cfg.AutoAuth.Method.Config)
		if err != nil {
			t.Fatal(err)
		}
		expectST := SecretsTable{
			registryToSecret: map[string]string{
				"registry-1.example.com": "secret/docker/creds",
				"registry-2.example.com": "secret/docker/extra/creds",
			},
		}
		if !reflect.DeepEqual(expectST, secretTable) {
			t.Fatalf("Expected secrets table %+v, got secrets table %+v", expectST, secretTable)
		}
		gotSecret := expectST.GetPath("registry-1.example.com")
		expectSecret := "secret/docker/creds"
		if expectSecret != gotSecret {
			t.Errorf("Secrets differ:\n%v", cmp.Diff(expectSecret, gotSecret))
		}
		gotSecret = expectST.GetPath("registry-2.example.com")
		expectSecret = "secret/docker/extra/creds"
		if expectSecret != gotSecret {
			t.Errorf("Secrets differ:\n%v", cmp.Diff(expectSecret, gotSecret))
		}
	})
}
