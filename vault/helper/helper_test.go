package helper

import (
        "os"
        "testing"

        vaultAPI "github.com/hashicorp/vault/api"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

func TestTODO(t *testing.T) {
        info := vault.NewVaultTestServerInfo(t)
        os.Setenv("VAULT_ADDR", info.Address)
        os.Setenv("VAULT_TOKEN", info.Token)

        client, err := vaultAPI.NewClient(nil)
        if err != nil {
                t.Fatalf("error creating new Vault API client: %v", err)
        }
        mySecret := map[string]interface{}{
                "foo": "bar",
        }
        _, err = client.Logical().Write("secret/foo/bar", mySecret)
        if err != nil {
                t.Fatalf("error writing secret: %v", err)
        }
}
