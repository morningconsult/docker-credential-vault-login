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
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNewLogWriter(t *testing.T) {
	cases := []struct {
		name   string
		pre    func(t *testing.T)
		config map[string]interface{}
		err    string
	}{
		{
			name: "log-dir-from-env",
			pre: func(t *testing.T) {
				t.Setenv(envLogDir, "testdata")
			},
			err: "",
		},
		{
			name: "log-dir-from-config",
			pre: func(t *testing.T) {
				t.Setenv(envLogDir, "")
				os.Unsetenv(envLogDir)
			},
			config: map[string]interface{}{"log_dir": "testdata"},
			err:    "",
		},
		{
			name:   "error-expanding-log-dir",
			config: map[string]interface{}{"log_dir": "~asdgweq"},
			err:    "error expanding logging directory : cannot expand user-specific home dir",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pre != nil {
				tc.pre(t)
			}

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
