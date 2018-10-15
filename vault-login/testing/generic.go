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

package test

import (
	"github.com/hashicorp/vault/helper/jsonutil"
	"os"
	"testing"
)

func ErrorsEqual(t *testing.T, got interface{}, expected string) {
	switch e := got.(type) {
	case string:
		if got != expected {
			t.Fatalf("returned unexpected error message.\nExpected:\n%q\n\nGot:\n%q",
				expected, got)
		}
	case error:
		if e.Error() != expected {
			t.Fatalf("returned unexpected error message.\nExpected:\n%q\n\nGot:\n%q",
				expected, e.Error())
		}
	default:
		t.Fatalf("bad type passed to test.ErrorsEqual()")
	}

}

func MakeFile(t *testing.T, name string, data []byte) {
	file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		t.Fatalf("error opening file %q: %v", name, err)
	}
	defer file.Close()

	if _, err = file.Write(data); err != nil {
		t.Fatalf("error writing data to file %q: %v", name, err)
	}
}

func DeleteFile(t *testing.T, name string) {
	if err := os.Remove(name); err != nil {
		t.Fatalf("error deleting file %q: %v", name, err)
	}
}

func EncodeJSON(t *testing.T, in interface{}) []byte {
	data, err := jsonutil.EncodeJSON(in)
	if err != nil {
		t.Fatalf("error encoding json: %v", err)
	}
	return data
}
