package vault

import "github.com/hashicorp/vault/api"

// ClientFactory is used to create a new vault.Client
// instance. Its methods (WithClient() and NewClient())
// will attempt to obtain a valid Vault token via the
// authentication method specified in the config.json
// file.
type ClientFactory interface {
	// WithClient receives a Vault API client and attempts
	// to give it a token using the method specified in
	// the config.json file. This method is primarily for
	// testing purposes
	WithClient(*api.Client) (Client, *api.Secret, error)

	// NewClient creates a new Vault API client and attempts
	// to give it a valid Vault token by authenticating against
	// against Vault using the method specified in the
	// config.json file
	NewClient() (Client, *api.Secret, error)
}
