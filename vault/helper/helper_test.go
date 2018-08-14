package helper

import (
        "fmt"
        "net/http"
        // "os"
        // "path"
        "testing"

        "github.com/hashicorp/vault/api"
        vaulthttp "github.com/hashicorp/vault/http"
        "github.com/hashicorp/vault/vault"
)

func TestHelperGet(t *testing.T) {
        var (
                secretPath = "secret/foo/bar"
                secret     = map[string]interface{}{
                        "username": "docker@user.com",
                        "password": "potato",
                }

        cluster := vault.NewTestCluster(t, &vault.CoreConfig{}, &vault.TestClusterOptions{
                HandlerFunc: vaulthttp.Handler,
        })
        cluster.Start()
        defer cluster.Cleanup()
        cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

        config := api.DefaultConfig()
        config.Address = fmt.Sprintf("https://127.0.0.1:%d", cores[0].Listeners[0].Address.Port)
        config.HttpClient.Transport.(*http.Transport).TLSClientConfig = cores[0].TLSConfig

        client, err := api.NewClient(config)
        if err != nil {
                t.Fatal(err)
        }
        client.SetToken(cluster.RootToken)

        _, err = client.Logical().Write(secretPath, secret)
        if err != nil {
                t.Fatal(err)
        }

        helper := NewHelper(secret, client)
        user, pw, err := helper.Get("")
        if err != nil {
                t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
        }
        if v, _ := secret["username"].(string); v != user {
                t.Errorf("Expected username %q, got %q", v, user)
        }
        if v, _ := secret["password"].(string); v != pw {
                t.Errorf("Expected password %q, got %q", v, pw)
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
        // user, pw, err := helper.Get("")
        // if err != nil {
        //         t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
        // }
        // if v, _ := secret["username"].(string); v != user {
        //         t.Errorf("Expected username %q, got %q", v, user)
        // }
        // if v, _ := secret["password"].(string); v != pw {
        //         t.Errorf("Expected password %q, got %q", v, pw)
//         }
// }

