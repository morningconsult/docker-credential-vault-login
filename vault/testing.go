package vault

import (
        "fmt"
        "os"
        "strconv"
        "testing"

        "github.com/hashicorp/vault/api"
)

var VaultDevPortString string

var VaultDevRootToken string

func initSecretsEngine(t *testing.T) (string, string) {
        if _, err := strconv.Atoi(VaultDevPortString); err != nil {
                t.Fatal("Vault listener port must be an integer")
        }
        if VaultDevRootToken == "" {
                t.Fatal("No Vault root token provided")
        }

        os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1:%s", VaultDevPortString))
        client, err := api.NewClient(nil)
        if err != nil {
                t.Fatalf("error initializing Vault API client: %v", err)
        }
        client.SetToken(VaultDevRootToken)

        disableSecretEngine(t, client)
        enableSecretEngine(t, client)
}

func disableSecretEngine(t *testing.T, client *api.Client) {
        if err := client.Sys().Unmount("secret"); err != nil {
                t.Fatalf("error unmounting \"secret\" mount: %v", err)
        }
}

func enableSecretEngine(t *testing.T, client *api.Client) {
        params := &api.MountInput{
                Type:    "kv",
                Options: map[string]string{
                        "version": "1",
                },
        }
        if err := client.Sys().Mount("secret", params); err != nil {
                t.Fatalf("error mounting \"secret\" mount: %v", err)
        }
}
