// Tests to write:
// * Order of file reading 

package config

import (
        "encoding/json"
        "os"
        "testing"
)

func TestReadsFileEnv(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile.json"  
        // create test file
        cfg := &CredHelperConfig{
                Method:   VaultAuthMethodAWS,
                Role:     "dev-role-iam",
                Path:     "secret/foo/bar",
                ServerID: "vault.example.com",
        }
        data := marshalJSON(t, cfg)
        makeFile(t, testFilePath, data)
        // defer deleteFile(t, testFilePath)

        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)
}

func marshalJSON(t *testing.T, v interface{}) []byte {
        v, err := json.Marshal(v)
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
