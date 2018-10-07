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

package helper

import (
	"fmt"
	"os"
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
		opts.CacheUtil = cache.NewCacheUtil(opts.VaultClient)
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
	defer log.Flush()

	// Parse the config.json file
	cfg, err := config.GetCredHelperConfig()
	if err != nil {
		log.Errorf("Error parsing configuration file: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// Handle according to the chosen authentication method
	switch cfg.Method {
	case config.VaultAuthMethodAWSIAM, config.VaultAuthMethodAWSEC2:
		// Get the cached token (if exists)
		cached, err := h.cacheUtil.GetCachedToken(cfg.Method)
		if err != nil {
			// Delete the token cache file
			h.cacheUtil.ClearCachedToken(cfg.Method)
			log.Errorf("error getting cached token: %v", err)
			log.Infof("deleted cached token file %s", h.cacheUtil.TokenFilename(cfg.Method))
		}

		// If an instance of cache.CachedToken was returned, check
		// if the token is expired or if it can be renewed before
		// attempting to use it to read the secret
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

		// If a valid cached token is found, attempt to get credentials
		// using it. If it fails, re-authenticate to obtain a new token
		// and try again.
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

		// Vault API client has no client token. Authenticate
		// against Vault to obtain a new one
		var factory vault.ClientFactory
		if cfg.Method == config.VaultAuthMethodAWSIAM {
			factory, err = vault.NewClientFactoryAWSIAMAuth(cfg.Role, cfg.ServerID, cfg.MountPath)
		} else {
			factory, err = vault.NewClientFactoryAWSEC2Auth(cfg.Role, cfg.MountPath)
		}
		if err != nil {
			log.Errorf("error creating new client factory: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}


		// Authenticate according to the selected method (if applicable)
		// and if successful give the resulting token to the Vault API
		// client.
		var (
			client  vault.Client
			secret  *api.Secret
		)
		if h.vaultAPI != nil {
			client, secret, err = factory.WithClient(h.vaultAPI)
		} else {
			client, secret, err = factory.NewClient()
		}
		if err != nil {
			log.Errorf("error authenticating against Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		// Attempt to cache the token; log if it fails but don't return
		// an error
		if err = h.cacheUtil.CacheNewToken(secret, cfg.Method); err != nil {
			log.Errorf("error caching new token: %v", err)
		}

		// Get the Docker credentials from Vault
		creds, err := client.GetCredentials(cfg.Secret)
		if err != nil {
			log.Errorf("error getting Docker credentials from Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		return creds.Username, creds.Password, nil
	case config.VaultAuthMethodToken:
		var vaultAPI *api.Client = h.vaultAPI
		if vaultAPI == nil || vaultAPI.Token() == "" {
			if os.Getenv(api.EnvVaultToken) == "" {
				log.Errorf("$%s is not set", api.EnvVaultToken)
				return "", "", credentials.NewErrCredentialsNotFound()
			}
			vaultAPI, err = api.NewClient(nil)
			if err != nil {
				log.Error(err)
				return "", "", credentials.NewErrCredentialsNotFound()
			}
		}
		
		// Get the Docker credentials from Vault
		client := vault.NewDefaultClient(vaultAPI)
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
