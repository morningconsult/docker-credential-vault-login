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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoadConfig(t *testing.T) {

	cases := []struct {
		name string
		file string
		err  string
	}{
		{
			"file-doesnt-exist",
			"testdata/nonexistent.hcl",
			"stat testdata/nonexistent.hcl: no such file or directory",
		},
		{
			"provided-directory",
			"testdata",
			"location is a directory, not a file",
		},
		{
			"empty-file",
			"testdata/empty-file.hcl",
			"no 'auto_auth' block found in configuration file",
		},
		{
			"no-method",
			"testdata/no-method.hcl",
			"error parsing 'auto_auth': error parsing 'method': one and only one \"method\" block is required",
		},
		{
			"no-sinks",
			"testdata/no-sinks.hcl",
			"",
		},
		{
			"no-mount-path",
			"testdata/no-mount-path.hcl",
			"",
		},
		{
			"valid",
			"testdata/valid.hcl",
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(tc.file)
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
