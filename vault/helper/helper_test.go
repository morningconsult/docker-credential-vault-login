package helper

import (
        "fmt"
        "os"
        "path"
        "testing"

        "github.com/hashicorp/vault/api"
        "github.com/hashicorp/vault/http"
        "github.com/hashicorp/vault/vault"
        "github.com/hashicorp/vault/logical"
        "github.com/hashicorp/vault/builtin/logical/transit"
        // vault "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

const ClusterPort int = 32010

func TestStartCluster(t *testing.T) {
        coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"transit": transit.Factory,
		},
		ClusterAddr: fmt.Sprintf("https://127.3.4.1:%d", ClusterPort),
        }

        cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
                HandlerFunc: http.Handler,
        })
        cluster.Start()
        defer cluster.Cleanup()
        cores := cluster.Cores

	// make it easy to get access to the active
	core := cores[0].Core
	vault.TestWaitActive(t, core)

        config := api.DefaultConfig()
        config.Address = coreConfig.ClusterAddr
        config.HttpClient.Transport.(*http.Transport).TLSClientConfig = core.TLSConfig

        client, err := api.NewClient(config)
        if err != nil {
                t.Fatal(err)
        }
        client.SetToken(cluster.RootToken)

        _, err = client.Logical().Write("secret/foo/bar", map[string]interface{}{"foo":"bar"})
        if err != nil {
                t.Fatal(err)
        }
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

