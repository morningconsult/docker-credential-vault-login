package helper

import (
        "os"
        "testing"

        api "github.com/hashicorp/vault/api"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

// func TestTODO(t *testing.T) {
//         var (
//                 path = "secret/foo/bar"
//                 secret = map[string]interface{}{
//                         "username": "docker.user@registry.com",
//                         "password": "my secure password",
//                 }
//         )

//         client := vault.NewTestClient(t)

//         // Write a secret to Vault dev server
//         resp := client.Write(path, secret)
//         testResponseStatus(t, resp, 200)

//         os.Setenv("VAULT_ADDR", client.Address())
//         os.Setenv("VAULT_TOKEN", client.Token())
//         vaultClient, err := api.NewClient(nil)
//         if err != nil {
//                 t.Fatalf("error creating new Vault API client: %v", err)
//         }
//         helper := NewHelper(path, vaultClient)
//         username, password, err := helper.Get("")
//         if err != nil {
//                 t.Fatalf("error reading credentials from Vault: %v", err)
//         }
//         t.Logf("Username: %s\nPassword: %s\n", username, password)
// }

func TestTODO(t *testing.T) {
        var (
                path = "secret/app/docker"
                secret = map[string]interface{}{
                        "username": "docker.user@registry.com",
                        "password": "potato",
                }
        )
        vault.InitSecretsEngine(t)

        os.Setenv("VAULT_ADDR", vault.Address())
        os.Setenv("VAULT_TOKEN", vault.Token())

        client, err := api.NewClient(nil)
        if err != nil {
                t.Fatalf("error creating new Vault API client: %v", err)
        }
        _, err = client.Logical().Write(path, secret)
        if err != nil {
                t.Fatalf("error writing secret to Vault: %v", err)
        }
        
        helper := NewHelper(path, client)
        user, pw, err := helper.Get("")
        if err != nil {
                t.Fatalf("error retrieving Docker credentials from Vault: %v")
        }
        t.Logf("Username: %s\nPassword: %s\n", user, pw)
}
