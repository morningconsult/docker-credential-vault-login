package helper

import (
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/vault"
)

var notImplementedError = fmt.Errorf("not implemented")

type HelperOptions struct {
	VaultClient *api.Client
	CacheUtil   cache.CacheUtil
}

type Helper struct {
	vaultAPI  *api.Client
	cacheUtil cache.CacheUtil
}

// Ensure Helper adheres to the credentials.Helper interface
var _ credentials.Helper = (*Helper)(nil)

// NewHelper creates a new Helper
func NewHelper(opts *HelperOptions) *Helper {
	if opts == nil {
		opts = &HelperOptions{}
	}

	if opts.CacheUtil == nil {
		opts.CacheUtil = cache.NewCacheUtil()
	}

	return &Helper{
		vaultAPI:  opts.VaultClient,
		cacheUtil: opts.CacheUtil,
	}
}

func (h *Helper) Add(creds *credentials.Credentials) error {
	return notImplementedError
}

func (h *Helper) Delete(serverURL string) error {
	return notImplementedError
}

func (h *Helper) Get(serverURL string) (string, string, error) {
	var cached *cache.CachedToken = nil

	// Parse the config.json file
	cfg, err := config.GetCredHelperConfig()
	if err != nil {
		log.Errorf("Error parsing configuration file: %v")
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// Get the cached token (if exists)
	if cfg.Method != config.VaultAuthMethodToken {
		cached, err = h.cacheUtil.GetCachedToken(cfg.Method)
		if err != nil {
			// Delete the token cache file
			h.cacheUtil.ClearCachedToken(cfg.Method)
			log.Errorf("error getting cached token: %v", err)
		}
	}

        // If an instance of cache.CachedToken was returned, check
        // if the token is expired or if it can be renewed before
        // attempting to use it to read the secret.
	var cachedTokenID = ""
	if cached != nil {
		if cached.Expired() {
			// Delete the cached token if expired
			h.cacheUtil.ClearCachedToken(cfg.Method)
		} else {
			cachedTokenID = cached.Token
			if cached.EligibleForRenewal() {
				err = h.cacheUtil.RenewToken(cached)
				if err != nil {
					// Delete the cached token if it failed to renew
					h.cacheUtil.ClearCachedToken(cfg.Method)
					cachedTokenID = ""
				}
			}
		}
	}

	// If a valid cached token is found, attempt to get
	// credentials using it. If it fails, re-authenticate
	// to obtain a new token and try again.
	if cachedTokenID != "" {
		var vaultAPI *api.Client
		if h.vaultAPI != nil {
			vaultAPI = h.vaultAPI
		} else {
			vaultAPI, err = api.NewClient(nil)
			if err != nil {
				log.Errorf("error creating Vault API client: %v", err)
				return "", "", credentials.NewErrCredentialsNotFound()
			}
		}
		vaultAPI.SetToken(cachedTokenID)
		client := vault.NewDefaultClient(vaultAPI)

		// Get the Docker credentials from Vault
		creds, err := client.GetCredentials(cfg.Secret)
		if err == nil {
			return creds.Username, creds.Password, nil
		}
		log.Errorf("error getting Docker credentials from Vault: %v", err)
		h.cacheUtil.ClearCachedToken(cfg.Method)
	}

	var (
                client  vault.Client
                factory vault.ClientFactory
                secret  *api.Secret
        )

        // Create a new vault.ClientFactory instance according
        // to the chosen authentication method
	switch cfg.Method {
	case config.VaultAuthMethodAWSIAM:
		factory, err = vault.NewClientFactoryAWSIAMAuth(cfg.Role, cfg.ServerID)
	case config.VaultAuthMethodAWSEC2:
		factory, err = vault.NewClientFactoryAWSEC2Auth(cfg.Role)
	case config.VaultAuthMethodToken:
		factory = vault.NewClientFactoryTokenAuth()
	default:
		return nil, fmt.Errorf("unknown authentication method: %q", cfg.Method)
	}

	if err != nil {
		return nil, fmt.Errorf("error creating new client factory: %v", err)
	}

        // Authenticate according to the selected method (if
        // applicable) and if successful give the resulting
        // token to the Vault API client.
	if h.vaultAPI != nil {
		client, secret, err = factory.WithClient(h.vaultAPI)
	} else {
		client, secret, err = factory.NewClient()
	}

	if err != nil {
		return nil, fmt.Errorf("error authenticating against Vault: %v", err)
	}

	if cfg.Method != config.VaultAuthMethodToken && secret != nil {
		err = h.cacheUtil.CacheNewToken(secret, cfg.Method)
		if err != nil {
			return nil, fmt.Errorf("error caching new token: %v", err)
		}
	}

	// Get the Docker credentials from Vault
	creds, err := client.GetCredentials(cfg.Secret)
	if err != nil {
		log.Errorf("error getting Docker credentials from Vault: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	return creds.Username, creds.Password, nil
}

func (h *Helper) List() (map[string]string, error) {
	return nil, notImplementedError
}

func (h *Helper) newClientWithNewToken(cfg *config.CredHelperConfig) (vault.Client, error) {
	var (
		factory vault.ClientFactory
		client  vault.Client
		secret  *api.Secret
		err     error
	)

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
		return nil, fmt.Errorf("unknown authentication method: %q", cfg.Method)
	}

	if err != nil {
		return nil, fmt.Errorf("error creating new client factory: %v", err)
	}

	// If Helper has a Vault API client already, create a new
	// DefaultClient using this existing client
	if h.vaultAPI != nil {
		client, secret, err = factory.WithClient(h.vaultAPI)
	} else {
		client, secret, err = factory.NewClient()
	}

	if err != nil {
		return nil, fmt.Errorf("error authenticating against Vault: %v", err)
	}

	if cfg.Method != config.VaultAuthMethodToken && secret != nil {
		err = h.cacheUtil.CacheNewToken(secret, cfg.Method)
		if err != nil {
			return nil, fmt.Errorf("error caching new token: %v", err)
		}
	}

	return client, nil
}
