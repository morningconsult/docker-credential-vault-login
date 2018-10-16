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

package cache

import (
	"bytes"
	"encoding/json"
	"net/url"
	"fmt"
	"log"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/mitchellh/mapstructure"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	EnvCacheDir     string = "DOCKER_CREDS_CACHE_DIR"
	EnvDisableCache string = "DOCKER_CREDS_DISABLE_CACHE"
	DefaultCacheDir string = "~/.docker-credential-vault-login"
	BackupCacheDir  string = "/tmp/.docker-credential-vault-login"
)

var mutex sync.RWMutex

type CacheUtil interface {
	CacheDir() string
	TokenFile() string
	LookupToken(string, config.VaultAuthMethod) (*CachedToken, error)
	CacheNewToken(*api.Secret, string, config.VaultAuthMethod) error
	ClearCachedToken(string, config.VaultAuthMethod)
	RenewToken(*CachedToken, *api.Client) error
}

// NewCacheUtil returns a new NullCacheUtil if the DOCKER_CREDS_DISABLE_CACHE
// environment variable is set. Otherwise, it returns a new DefaultCacheUtil.
func NewCacheUtil(cacheDir string) CacheUtil {
	// Environmental variable takes precedence over config file
	if disableCache, err := strconv.ParseBool(os.Getenv(EnvDisableCache)); err == nil {
		if disableCache {
			return NewNullCacheUtil(cacheDir)
		}
	}
	return NewDefaultCacheUtil(cacheDir)
}

type DefaultCacheUtil struct {
	cacheDir      string
	tokenFilename string
}

// NewDefaultCacheUtil creates a new CacheUtil object. It will store tokens
// at the cacheDir directory
func NewDefaultCacheUtil(cacheDir string) *DefaultCacheUtil {
	if cacheDir == "" {
		cacheDir = SetupCacheDir()
	}

	return &DefaultCacheUtil{
		cacheDir:      cacheDir,
		tokenFilename: filepath.Join(cacheDir, "tokens.json"),
	}
}

// GetCacheDir returns the cache directory
func (c *DefaultCacheUtil) CacheDir() string {
	return c.cacheDir
}

// TokenFile returns the name of the file in which cached tokens are stored
func (c *DefaultCacheUtil) TokenFile() string {
	return c.tokenFilename
}
// RenewToken attempts to renew a Vault client token. If successful, it will
// update the token's expiration date and write the file to disk ("cache"
// the token). If it fails, it will return an error.
func (c *DefaultCacheUtil) RenewToken(cached *CachedToken, client *api.Client) error {
	var err error

	if client == nil {
		return fmt.Errorf("no Vault client provided")
	}

	originalToken := client.Token()
	client.SetToken(cached.TokenID())
	defer client.SetToken(originalToken)

	// Renew the token
	secret, err := client.Auth().Token().RenewSelf(0)
	if err != nil {
		return err
	}

	// Cache the token
	return c.CacheNewToken(secret, client.Address(), cached.AuthMethod())
}

// LookupToken attempts to retrieve a cached token that corresponds to the given
// host-method. If no token is found for the given host-method combination, it
// will return a nil *CachedToken and a nil error. If the file is in any way
// malformed, it will return a nil *CachedToken and an error.
func (c *DefaultCacheUtil) LookupToken(vaultAddr string, method config.VaultAuthMethod) (*CachedToken, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	file, err := os.Open(c.tokenFilename)
	if err != nil {
		if os.IsNotExist(err) {
			// No token cache file found
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	// Decode cached tokens
	var tokenFile = make(map[string]interface{})
	if err = jsonutil.DecodeJSONFromReader(file, &tokenFile); err != nil {
		return nil, fmt.Errorf("error JSON-decoding token file %s: %v", c.tokenFilename, err)
	}

	u, err := url.Parse(vaultAddr)
	if err != nil {
		return nil, fmt.Errorf("error parsing Vault server URL %q: %v", vaultAddr, err)
	}
	host := u.Host
	
	v, ok := tokenFile[host]
	if !ok {
		// No tokens for this host
		return nil, nil
	}

	serverTokens, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cached token is malformed (host: %q)", host)
	}

	t, ok := serverTokens[string(method)]
	if !ok {
		// No token for this server-method combination
		return nil, nil
	}

	tokenMap, ok := t.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("cached token is malformed (host: %q, method: %q)", host, string(method))
	}

	// Decode cached token from JSON into a *CachedToken instance
	var token = new(CachedToken)
	if err = mapstructure.Decode(tokenMap, token); err != nil {
		return nil, fmt.Errorf("error decoding cached token: %v", err)
	}

	if token.TokenID() == "" {
		return nil, fmt.Errorf("no token found (host: %s, method: %s)", host, string(method))
	}

	if token.ExpirationTS() == 0 {
		return nil, fmt.Errorf("token has no expiration date (host: %s, method: %s)", host, string(method))
	}

	token.SetAuthMethod(method)
	token.SetVaultHost(host)

	return token, nil
}

// CacheNewToken accepts either a *CachedToken or a
// *github.com/hashicorp/vault/api.Secret and writes it to disk ("caches it")
// for use in future Vault API calls. Tokens are cached according to the address
// of the Vault server from which it was created and method of authentication
// by which it was created, for example:
// {
//     "vault.service.consul": {
//         "iam": {
//             "token": "694c1667-bac3-481f-8383-ae300b879302",
//             "expiration": 1539709042,
//             "renewable": true
//         },
//         "ec2": {
//             "token": "0f1288cf-e4fa-4965-af4c-ddc27ae22aa9",
//             "expiration": 1539709092,
//             "renewable": false
//         }
// }
func (c *DefaultCacheUtil) CacheNewToken(secret *api.Secret, vaultAddr string, method config.VaultAuthMethod) error {
	var (
		token *CachedToken
		err   error
	)

	token, err = c.buildCachedTokenFromSecret(secret, method, vaultAddr)
	if err != nil {
		return fmt.Errorf("error creating cache.CachedToken instance from a *github.com/hashicorp/vault/api.Secret instance: %v", err)
	}

	err = c.writeTokenToFile(token)
	if err != nil {
		return fmt.Errorf("error writing cache.CachedToken instance to disk: %v", err)
	}
	return nil
}

// ClearCachedToken deletes all cached tokens associated with the given
// Vault host-authentication method combination.
func (c *DefaultCacheUtil) ClearCachedToken(vaultAddr string, method config.VaultAuthMethod) {
	mutex.Lock()
	defer mutex.Unlock()

	file, err := os.OpenFile(c.tokenFilename, os.O_RDWR, 0600)
	if err != nil {
		return
	}

	var tokenFile = make(map[string]interface{})
	if err = jsonutil.DecodeJSONFromReader(file, &tokenFile); err != nil {
		file.Close()
		os.Remove(c.tokenFilename)
		return
	}

	u, err := url.Parse(vaultAddr)
	if err != nil {
		file.Close()
		return
	}
	host := u.Host

	serverTokens, ok := tokenFile[host].(map[string]interface{})
	if !ok {
		file.Close()
		return
	}

	delete(serverTokens, string(method))

	tokenFile[host] = serverTokens

	if err = c.writePrettyJSON(file, tokenFile); err != nil {
		file.Close()
		os.Remove(c.tokenFilename)
		return
	}

	file.Close()
}

func (c *DefaultCacheUtil) buildCachedTokenFromSecret(secret *api.Secret,
	method config.VaultAuthMethod, vaultAddr string) (*CachedToken, error) {

	// Get the token from the secret
	token, err := secret.TokenID()
	if err != nil {
		return nil, err
	}

	// Get the token's TTL
	ttl, err := secret.TokenTTL()
	if err != nil {
		return nil, err
	}
	expiration := time.Now().Add(ttl).Unix()

	// Get the token's renewability
	renewable, err := secret.TokenIsRenewable()
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(vaultAddr)
	if err != nil {
		return nil, err
	}

	return &CachedToken{
		Token:      token,
		Expiration: expiration,
		Renewable:  renewable,
		host:       u.Host,
		method:     method,
	}, nil
}

func (c *DefaultCacheUtil) writeTokenToFile(token *CachedToken) error {
	mutex.Lock()
	defer mutex.Unlock()

	// Create the token cache directory and its parents in case they don't
	// already exist
	if err := os.MkdirAll(filepath.Dir(c.tokenFilename), 0700); err != nil {
		return err
	}

	// Open the cached token or create it if it doesn't already exist
	file, err := os.OpenFile(c.tokenFilename, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	var tokenFile = make(map[string]interface{})

	// Ignore error DecodeJSONFromReader returns. If there is an error
	// decoding the file into a map[string]interface{}, then the file is
	// malformed anyways so it will just overwrite the entire file
	jsonutil.DecodeJSONFromReader(file, &tokenFile)

	host := token.VaultHost()
	var serverTokens = make(map[string]interface{})
	if t, ok := tokenFile[host].(map[string]interface{}); ok {
		serverTokens = t
	}

	serverTokens[string(token.AuthMethod())] = token.ToMap()
	tokenFile[host] = serverTokens

	return c.writePrettyJSON(file, tokenFile)
}

func (c *DefaultCacheUtil) writePrettyJSON(file *os.File, v interface{}) error {
	// JSON-encode the interface{} v
	data, err := jsonutil.EncodeJSON(v)
	if err != nil {
		return err
	}

	// Change the file size to 0 to overwrite all file contents
	if err = file.Truncate(0); err != nil {
		return err
	}

	// Reset the I/O offset to the beginning of the file
	if _, err = file.Seek(0, 0); err != nil {
		return err
	}

	var out bytes.Buffer
	if err = json.Indent(&out, data, "", "    "); err == nil {
		_, err = file.Write(out.Bytes())
	} else {
		_, err = file.Write(data)
	}
	return err
}

// NullCacheUtil conforms to the CacheUtil interface and implements stub
// functions (with the exception of GetCacheDir())
type NullCacheUtil struct {
	cacheDir string
	tokenFilename string
}

// NewNullCacheUtil creates a new CacheUtil object. The value of its cacheDir
// field is set to the value of the DOCKER_CREDS_CACHE_DIR environment variable
// if it is set. Otherwise, it uses the default directory.
func NewNullCacheUtil(cacheDir string) *NullCacheUtil {
	if cacheDir == "" {
		cacheDir = SetupCacheDir()
	}
	return &NullCacheUtil{
		cacheDir: cacheDir,
		tokenFilename: filepath.Join(cacheDir, "tokens.json"),
	}
}

func (n *NullCacheUtil) CacheDir() string {
	return n.cacheDir
}

func (n *NullCacheUtil) TokenFile() string {
	return n.tokenFilename
}

func (n *NullCacheUtil) LookupToken(host string, method config.VaultAuthMethod) (*CachedToken, error) {
	return nil, nil
}

func (n *NullCacheUtil) CacheNewToken(secret *api.Secret, vaultAddr string, method config.VaultAuthMethod) error {
	return nil
}

func (n *NullCacheUtil) ClearCachedToken(addr string, method config.VaultAuthMethod) {
	return
}

func (n *NullCacheUtil) RenewToken(token *CachedToken, client *api.Client) error {
	return nil
}

// configDir should be the value of cache.dir directly from the config.json file
func SetupCacheDir() string {
	var cacheDirRaw = DefaultCacheDir
	if v := os.Getenv(EnvCacheDir); v != "" {
		cacheDirRaw = v
	}

	cacheDir, err := homedir.Expand(cacheDirRaw)
	if err != nil {
		log.Printf("Failed to create cache file at %s.\nCreating log file at %s instead.\n",
			cacheDirRaw, BackupCacheDir)
		cacheDir = BackupCacheDir
	}

	cleaned := filepath.Clean(cacheDir)

	if _, err = os.Stat(cleaned); err != nil {
		os.MkdirAll(cleaned, 0700)
	}
	return cleaned
}
