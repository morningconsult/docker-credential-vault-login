package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"os"
)

// ClientFactoryTokenAuth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained from
// the VAULT_TOKEN environment variable.
type ClientFactoryTokenAuth struct{}

func NewClientFactoryTokenAuth() ClientFactory {
	return &ClientFactoryTokenAuth{}
}

// NewClient creates a new Vault API client. It expects the various Vault
// environment variables to be set as necessary (e.g. VAULT_TOKEN,
// VAULT_ADDR, etc.). If the VAULT_TOKEN environment variable is not set,
// NewClient will return an error. Otherwise, it will return a
// DefaultClient object.
func (c *ClientFactoryTokenAuth) NewClient() (Client, *api.Secret, error) {
	// Create a new Vault API client
	client, err := api.NewClient(nil)
	if err != nil {
		return nil, nil, err
	}

	// Check if the Vault API client has a token.
	// If not, raise an error.
	if v := client.Token(); v == "" {
		return nil, nil, fmt.Errorf("%s %s %s",
			"Vault API client has no token. Make sure to set the token using the",
			api.EnvVaultToken, "environment variable")
	}

	return NewDefaultClient(client), nil, nil
}

// WithClient retrieves the environment variable set by the VAULT_TOKEN
// environment variable and sets the Vault API client with this token
// and returns a DefaultClient object. Note that this will overwrite
// the client's existing token if it has one. This function is primarily
// used for testing purposes.
func (c *ClientFactoryTokenAuth) WithClient(client *api.Client) (Client, *api.Secret, error) {
	if v := os.Getenv(api.EnvVaultToken); v != "" {
		client.SetToken(v)
	} else {
		return nil, nil, fmt.Errorf("%s environment variable is not set", api.EnvVaultToken)
	}

	return NewDefaultClient(client), nil, nil
}
