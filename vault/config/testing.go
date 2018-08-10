package config

import (
        "encoding/json"
        "os"
        "testing"
)

func errorsEqual(t *testing.T, got error, expected string) {
        gotErrMsg := got.Error()
        if gotErrMsg != expected {
                t.Errorf("GetCredHelperConfig returned unexpected error message.\nExpected:\n%q\n\nGot:\n%q",
                        expected, gotErrMsg)
        }
}

func marshalJSON(t *testing.T, v interface{}) []byte {
        data, err := json.Marshal(v)
        if err != nil {
                t.Fatalf("error marshaling JSON: %v", err)
        }
        return data
}

func makeFile(t *testing.T, name string, data []byte) {
        file, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0666)
        if err != nil {
                t.Fatalf("error opening file %q: %v", name, err)
        }
        defer file.Close()

        if _, err = file.Write(data); err != nil {
                t.Fatalf("error writing data to file %q: %v", name, err)
        }
}

func deleteFile(t *testing.T, name string) {
        if err := os.Remove(name); err != nil {
                t.Fatalf("error deleting file %q: %v", name, err)
        }
}
