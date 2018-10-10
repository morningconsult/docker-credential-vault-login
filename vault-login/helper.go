// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//         https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package vault

import (
	"fmt"
	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/auth"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"os"
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
func NewHelper(opts *HelperOptions) (*Helper, error) {
	var err error

	if opts == nil {
		opts = &HelperOptions{}
	}

	// Create a new Vault API client
	if opts.VaultClient == nil {
		opts.VaultClient, err = api.NewClient(nil)
		if err != nil {
			return nil, err
		}
	}

	if opts.CacheUtil == nil {
		opts.CacheUtil = cache.NewCacheUtil(opts.VaultClient)
	}

	return &Helper{
		vaultAPI:  opts.VaultClient,
		cacheUtil: opts.CacheUtil,
	}, nil
}

func (h *Helper) Add(creds *credentials.Credentials) error {
	return notImplementedError
}

func (h *Helper) Delete(serverURL string) error {
	return notImplementedError
}

func (h *Helper) Get(serverURL string) (string, string, error) {
	defer log.Flush()

	// Parse the config.json file
	cfg, err := config.GetCredHelperConfig()
	if err != nil {
		log.Errorf("error parsing configuration file: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// Handle according to the chosen authentication method
	switch cfg.Method {
	case config.VaultAuthMethodAWSIAM, config.VaultAuthMethodAWSEC2:
		// If a valid cached token is found, attempt to read secret with it
		if token := h.getCachedToken(cfg.Method); token != "" {
			h.vaultAPI.SetToken(token)
			client := auth.NewDefaultClient(h.vaultAPI)
			creds, err := client.GetCredentials(cfg.Secret)
			if err == nil {
				return creds.Username, creds.Password, nil
			}
			log.Debugf("error getting Docker credentials from Vault using cached token: %v", err)
			h.cacheUtil.ClearCachedToken(cfg.Method)
		}

		// Authenticate against Vault in the manner specified in the
		// config.json file to obtain a new client token
		var factory auth.ClientFactory
		if cfg.Method == config.VaultAuthMethodAWSIAM {
			factory, err = auth.NewClientFactoryAWSIAMAuth(cfg.Role, cfg.ServerID, cfg.MountPath)
		} else {
			factory, err = auth.NewClientFactoryAWSEC2Auth(cfg.Role, cfg.MountPath)
		}
		if err != nil {
			log.Errorf("error creating new client factory: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		client, secret, err := factory.Authenticate(h.vaultAPI)
		if err != nil {
			log.Errorf("error authenticating against Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		// Attempt to cache the token; log if it fails but don't return
		// an error
		if err = h.cacheUtil.CacheNewToken(secret, cfg.Method); err != nil {
			log.Debugf("error caching new token: %v", err)
		}

		// Get the Docker credentials from Vault
		creds, err := client.GetCredentials(cfg.Secret)
		if err != nil {
			log.Errorf("error getting Docker credentials from Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}
		return creds.Username, creds.Password, nil
	case config.VaultAuthMethodToken:
		// If the Vault API client doesn't have a token,
		// attempt to get it from $VAULT_TOKEN
		if h.vaultAPI.Token() == "" {
			token := os.Getenv(api.EnvVaultToken)
			if token == "" {
				log.Errorf("$%s is not set", api.EnvVaultToken)
				return "", "", credentials.NewErrCredentialsNotFound()
			}
			h.vaultAPI.SetToken(token)
		}

		// Get the Docker credentials from Vault
		client := auth.NewDefaultClient(h.vaultAPI)
		creds, err := client.GetCredentials(cfg.Secret)
		if err != nil {
			log.Errorf("error getting Docker credentials from Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}
		return creds.Username, creds.Password, nil
	default:
		log.Errorf("unknown authentication method: %q", cfg.Method)
		return "", "", credentials.NewErrCredentialsNotFound()
	}
}

func (h *Helper) List() (map[string]string, error) {
	return nil, notImplementedError
}

// getCachedToken attempts to retrieve a cached token. This function serves to
// abstract several of DefaultCacheUtil's methods so that to the caller it seems
// they are simply either receiving a token or no token, while underneath the
// hood several things are happening. First, it will attempt to lookup a token.
// If an error occurs during the lookup, it will log the error and remove any
// tokens associated with that authentication method. If a token is found, it
// will check if it is expired and remove cached tokens if it is indeed expired.
// If the token is not expired but renewable, it will attempt to renew the token.
// If it fails to renew, it will remove the cached tokens associated with the
// given method.
func (h *Helper) getCachedToken(method config.VaultAuthMethod) string {
	defer log.Flush()

	// Get the cached token (if exists)
	token, err := h.cacheUtil.LookupToken(method)
	if err != nil {
		// Log error and delete cached token
		log.Warnf("error getting cached token: %v", err)
		h.cacheUtil.ClearCachedToken(method)
	}

	// If an instance of cache.CachedToken was returned, check
	// if the token is expired or if it can be renewed before
	// attempting to use it to read the secret
	var tokenID = ""
	if token != nil {
		if token.Expired() {
			// Delete the cached token
			h.cacheUtil.ClearCachedToken(method)
		} else {
			tokenID = token.Token
			if token.EligibleForRenewal() {
				err = h.cacheUtil.RenewToken(token)
				if err != nil {
					// Log error and delete cached token
					log.Warnf("error attempting to renew token: %v", err)
					h.cacheUtil.ClearCachedToken(method)
					tokenID = ""
				}
			}
		}
	}
	return tokenID
}
