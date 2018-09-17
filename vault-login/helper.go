package helper

import (
	"fmt"

	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/vault"
)

var notImplementedError = fmt.Errorf("not implemented")

type Helper struct {
	vaultAPI *api.Client
}

// Ensure Helper adheres to the credentials.Helper interface
var _ credentials.Helper = (*Helper)(nil)

func NewHelper(client *api.Client) *Helper {
	return &Helper{
		vaultAPI: client,
	}
}

func (h *Helper) Add(creds *credentials.Credentials) error {
	return notImplementedError
}

func (h *Helper) Delete(serverURL string) error {
	return notImplementedError
}

func (h *Helper) Get(serverURL string) (string, string, error) {
	var (
		factory vault.ClientFactory
		client  vault.Client
	)

	// Parse the config.json file
	cfg, err := config.GetCredHelperConfig()
	if err != nil {
		log.Errorf("Error parsing configuration file: %v")
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// If the Helper does not already have a Vault API client
	// or if it has a client but the client has no Vault token,
	// create a Vault API client factory based on the type of
	// authentication method specified in the config file
	switch cfg.Method {
	case config.VaultAuthMethodAWSIAM:
		factory, err = vault.NewClientFactoryAWSIAMAuth(cfg.Role, cfg.ServerID)
	case config.VaultAuthMethodAWSEC2:
		factory, err = vault.NewClientFactoryAWSEC2Auth(cfg.Role)
	case config.VaultAuthMethodToken:
		factory = vault.NewClientFactoryTokenAuth()
	default:
		log.Errorf("Unknown authentication method: %q", cfg.Method)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	if err != nil {
		log.Errorf("Error creating new client factory: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// If Helper has a Vault API client already, create a new
	// DefaultClient using this existing client
	if h.vaultAPI != nil {
		client, err = factory.WithClient(h.vaultAPI)
	} else {
		client, err = factory.NewClient()
	}

	if err != nil {
		log.Errorf("Error creating a new Vault client: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// Get the Docker credentials from Vault
	creds, err := client.GetCredentials(cfg.Secret)
	if err != nil {
		log.Errorf("Error getting Docker credentials from Vault: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	return creds.Username, creds.Password, nil
}

func (h *Helper) List() (map[string]string, error) {
	return nil, notImplementedError
}
