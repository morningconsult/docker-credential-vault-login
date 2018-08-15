package helper

import (
	"fmt"
	"net/http"
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

func TestHelperGetsCreds(t *testing.T) {
	var (
		secretPath = "secret/foo/bar"
		secret     = map[string]interface{}{
			"username": "docker@user.com",
			"password": "potato",
		}
	)
        
        cluster := startTestCluster(t)
	defer cluster.Cleanup()
        
        client := newClient(t, cluster)

	_, err = client.Logical().Write(secretPath, secret)
	if err != nil {
		t.Fatal(err)
	}

	helper := NewHelper(secretPath, client)
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
}

func TestHelperFailsWhenNoCreds(t *testing.T) {
        cluster := startTestCluster(t)
        defer cluster.Cleanup()

        client := newClient(t, cluster)

        helper := NewHelper("secret/foo/bar", client)
        user, pw, err := helper.Get("")
        if err != nil {
                t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
        }
}

func startTestCluster(t *testing.T) *vault.TestCluster {
        base := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(log.Error),
	}

	cluster := vault.NewTestCluster(t, base, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
        cluster.Start()
        return cluster
}

func newClient(t *testing.T, cluster *vault.TestCluster) *api.Client {
        cores := cluster.Cores

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
        return client
}