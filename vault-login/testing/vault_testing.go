package test

import (
	"fmt"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
	"net/http"
	"testing"
)

func StartTestCluster(t *testing.T) *vault.TestCluster {
	base := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(log.Error),
	}

	cluster := vault.NewTestCluster(t, base, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	return cluster
}

// NewPreConfiguredVaultClient creates a new Vault API client and configures it to use
// the same settings as the vault.TestCluster
func NewPreConfiguredVaultClient(t *testing.T, cluster *vault.TestCluster) *api.Client {
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

func WriteSecret(t *testing.T, client *api.Client, secretPath string, secret map[string]interface{}) {
	if _, err := client.Logical().Write(secretPath, secret); err != nil {
		t.Fatal(err)
	}
}
