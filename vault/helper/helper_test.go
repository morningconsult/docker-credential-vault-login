package helper

import (
        "os"
        "testing"

        "github.com/hashicorp/vault/api"
        "github.com/hashicorp/vault/vault"
        // vault "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)


func TestStartCluster(t *testing.T) {
        cluster := vault.NewTestCluster(t, nil, nil)
        _, _, addr, err := cluster.Cores[0].Leader()
        if err != nil {
                t.Fatalf("error getting TestCluster leader: %v", err)
        }

        token := cluster.RootToken
        capath := cluster.TempDir

        go cluster.Start()
        defer cluster.Cleanup()

        os.Setenv("VAULT_ADDR", addr)
        os.Setenv("VAULT_TOKEN", token)
        os.Setenv("VAULT_CAPATH", capath)

        client, err := api.NewClient(nil)
        if err != nil {
                t.Fatalf("error initializing Vault API client: %v", err)
        }

        client.Logical().Write("secret/foo/bar", map[string]interface{}{"foo":"bar"})
}

// func TestHelperGet(t *testing.T) {
//         var (
//                 path = "secret/app/docker"
//                 secret = map[string]interface{}{
//                         "username": "docker.user@registry.com",
//                         "password": "potato",
//                 }
//         )
//         addr, token := vault.InitSecretsEngine(t)

//         os.Setenv("VAULT_ADDR", addr)
//         os.Setenv("VAULT_TOKEN", token)

//         client, err := api.NewClient(nil)
//         if err != nil {
//                 t.Fatalf("error creating new Vault API client: %v", err)
//         }
//         _, err = client.Logical().Write(path, secret)
//         if err != nil {
//                 t.Fatalf("error writing secret to Vault: %v", err)
//         }

//         helper := NewHelper(path, client)
//         user, pw, err := helper.Get("")
//         if err != nil {
//                 t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
//         }
//         if v, _ := secret["username"].(string); v != user {
//                 t.Errorf("Expected username %q, got %q", v, user)
//         }
//         if v, _ := secret["password"].(string); v != pw {
//                 t.Errorf("Expected password %q, got %q", v, pw)
//         }
// }

