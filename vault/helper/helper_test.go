package helper

import (
        "strconv"
        "testing"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

func TestTODO(t *testing.T) {
        port, err := strconv.Atoi(vault.VaultDevPort)
        if err != nil {
                t.Fatalf("strconv.Atoi failed: %v", err)
        }
        t.Logf("Test port: %d\n", port)
}