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
			_, err := buildSinks(tc.configs, logger, client)
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
			_, err := buildAuthMethod(tc.config, logger)
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
