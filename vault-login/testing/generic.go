package test

import (
	"os"
	"testing"
	"github.com/hashicorp/vault/helper/jsonutil"
)

func ErrorsEqual(t *testing.T, got interface{}, expected string) {
	switch e := got.(type) {
	case string:
		if got != expected {
			t.Fatalf("GetCredHelperConfig returned unexpected error message.\nExpected:\n%q\n\nGot:\n%q",
				expected, got)
		}
	case error:
		if e.Error() != expected {
			t.Fatalf("GetCredHelperConfig returned unexpected error message.\nExpected:\n%q\n\nGot:\n%q",
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