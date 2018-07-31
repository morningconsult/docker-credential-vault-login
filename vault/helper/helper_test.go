package helper

import (
        "io/ioutil"
        "strconv"
        "testing"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

func TestTODO(t *testing.T) {
        port, err := strconv.Atoi(vault.VaultDevPort)
        if err != nil {
                t.Fatalf("strconv.Atoi failed: %v\n", err)
        }
        t.Logf("Test port: %d\n", port)

        data, err := ioutil.ReadFile("testdata/vault_dev_server_output.txt")
        if err != nil {
                t.Fatalf("ReadFile failed: %v\n", err)
        }
        t.Logf("Vault Data:\n\n***\n\n%s\n***\n\n", string(data))
}