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
	"flag"
	"fmt"
	golog "log"
	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/auth"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/logging"
	"os"
	"strings"
)

var notImplementedError = fmt.Errorf("not implemented")

type HelperOptions struct {
	VaultAPI *api.Client
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

	return &Helper{
		vaultAPI:  opts.VaultAPI,
	}
}

func (h *Helper) VaultClient() *api.Client {
	return h.vaultAPI
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
	cfg, err := config.ParseConfigFile()
	if err != nil {
		golog.Printf("error parsing configuration file: %v", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	// Build cache directory
	cacheDir := cache.SetupCacheDir(cfg.Cache.Dir)

	// Create a new cache.CacheUtil
	h.cacheUtil = cache.NewCacheUtil(cacheDir, cfg.Cache.DisableTokenCaching)

	// Set up seelog
	h.setupLogger(cacheDir)

	// Create a new Vault client if this Helper has none
	if h.vaultAPI == nil {
		if err := h.newVaultClient(cfg.Client); err != nil {
			log.Errorf("error creating Vault client: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}
	}

	// Authenticate and obtain a new auth.Client according to the
	// specified method
	var client auth.Client
	switch cfg.Auth.Method {
	case config.VaultAuthMethodAWSIAM, config.VaultAuthMethodAWSEC2:
		// If a valid cached token is found, attempt to read secret with it
		if token := h.getCachedToken(h.vaultAPI.Address(), cfg.Auth.Method); token != "" {
			h.vaultAPI.SetToken(token)
			client = auth.NewDefaultClient(h.vaultAPI)
			creds, err := client.GetCredentials(cfg.Secret)
			if err == nil {
				return creds.Username, creds.Password, nil
			}
			log.Debugf("error getting Docker credentials from Vault using cached token: %v", err)
			h.cacheUtil.ClearCachedToken(h.vaultAPI.Address(), cfg.Auth.Method)
		}

		// Authenticate against Vault in the manner specified in the
		// config.json file to obtain a new client token
		var factory auth.ClientFactory
		if cfg.Auth.Method == config.VaultAuthMethodAWSIAM {
			factory, err = auth.NewClientFactoryAWSIAMAuth(cfg.Auth.Role, cfg.Auth.ServerID, cfg.Auth.AWSMountPath)
		} else {
			factory, err = auth.NewClientFactoryAWSEC2Auth(cfg.Auth.Role, cfg.Auth.AWSMountPath)
		}
		if err != nil {
			log.Errorf("error creating new client factory: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		var secret *api.Secret
		client, secret, err = factory.Authenticate(h.vaultAPI)
		if err != nil {
			log.Errorf("error authenticating against Vault: %v", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		// Attempt to cache the token; log if it fails but don't return
		// an error
		if err = h.cacheUtil.CacheNewToken(secret, h.vaultAPI.Address(), cfg.Auth.Method); err != nil {
			log.Debugf("error caching new token: %v", err)
		}
	case config.VaultAuthMethodToken:
		// If the Vault API client doesn't have a token, attempt to
		// get it from $VAULT_TOKEN
		if h.vaultAPI.Token() == "" {
			token := os.Getenv(api.EnvVaultToken)
			if token == "" {
				log.Errorf("$%s is not set", api.EnvVaultToken)
				return "", "", credentials.NewErrCredentialsNotFound()
			}
			h.vaultAPI.SetToken(token)
		}

		// Get the Docker credentials from Vault
		client = auth.NewDefaultClient(h.vaultAPI)
	default:
		log.Errorf("unknown authentication method: %q", cfg.Auth.Method)
		return "", "", credentials.NewErrCredentialsNotFound()
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

func (h *Helper) newVaultClient(vaultConfig map[string]string) error {
	vaultEnvVars := []string{
		api.EnvVaultAddress,
		api.EnvVaultCACert,
		api.EnvVaultClientCert,
		api.EnvVaultClientKey,
		api.EnvVaultClientTimeout,
		api.EnvVaultInsecure,
		api.EnvVaultTLSServerName,
		api.EnvVaultMaxRetries,
		api.EnvVaultToken,
	}

	for _, env := range vaultEnvVars {
		v, ok := vaultConfig[strings.ToLower(env)]
		if ok && v != "" && os.Getenv(env) == "" {
			os.Setenv(env, v)
			defer os.Unsetenv(env)
		}
	}

	client, err := api.NewClient(nil)
	if err != nil {
		return err
	}

	h.vaultAPI = client

	return nil
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
func (h *Helper) getCachedToken(vaultAddr string, method config.VaultAuthMethod) string {
	defer log.Flush()

	// Get the cached token (if exists)
	token, err := h.cacheUtil.LookupToken(vaultAddr, method)
	if err != nil {
		// Log error and delete cached token
		log.Warnf("error getting cached token: %v", err)
		h.cacheUtil.ClearCachedToken(vaultAddr, method)
		return ""
	}

	if token == nil {
		return ""
	}
	
	if token.Expired() {
		// Delete the cached token
		h.cacheUtil.ClearCachedToken(vaultAddr, method)
		return ""
	}

	if token.EligibleForRenewal() {
		if err = h.cacheUtil.RenewToken(token, h.vaultAPI); err != nil {
			// Log error and delete cached token
			log.Warnf("error attempting to renew token: %v", err)
			h.cacheUtil.ClearCachedToken(vaultAddr, method)
			return ""
		}
	}

	return token.TokenID()
}

func (h *Helper) setupLogger(cacheDir string) {
	if flag.Lookup("test.v") == nil {
		logging.SetupLogger(cacheDir)
	} else {
		logging.SetupTestLogger()
	}
}
