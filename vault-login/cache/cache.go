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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	EnvCacheDir     string = "DOCKER_CREDS_CACHE_DIR"
	EnvDisableCache string = "DOCKER_CREDS_DISABLE_CACHE"
	EnvCipherKey    string = "DOCKER_CREDS_CACHE_ENCRYPTION_KEY"
	DefaultCacheDir string = "~/.docker-credential-vault-login"
	BackupCacheDir  string = "/tmp/.docker-credential-vault-login"
)

var mutex sync.RWMutex

type CacheUtil interface {
	GetCacheDir() string
	LookupToken(config.VaultAuthMethod) (*CachedToken, error)
	CacheNewToken(interface{}, config.VaultAuthMethod) error
	ClearCachedToken(config.VaultAuthMethod)
	RenewToken(*CachedToken) error
	TokenFilename(config.VaultAuthMethod) string
}

// NewCacheUtil returns a new NullCacheUtil if the DOCKER_CREDS_DISABLE_CACHE
// environment variable is set. Otherwise, it returns a new DefaultCacheUtil.
func NewCacheUtil(vaultAPI *api.Client) CacheUtil {
	if disableCache, err := strconv.ParseBool(os.Getenv(EnvDisableCache)); err == nil {
		if disableCache {
			return NewNullCacheUtil()
		}
	}
	return NewDefaultCacheUtil(vaultAPI)
}

type DefaultCacheUtil struct {
	cacheDir      string
	tokenCacheDir string
	vaultAPI      *api.Client
	block         cipher.Block
}

// NewDefaultCacheUtil creates a new CacheUtil object. The value of its cacheDir
// field is set to the value of the DOCKER_CREDS_CACHE_DIR environment variable
// if it is set. Otherwise, it uses the default directory.
func NewDefaultCacheUtil(vaultAPI *api.Client) *DefaultCacheUtil {
	var block cipher.Block = nil
	if v := os.Getenv(EnvCipherKey); v != "" {
		if len(v) > 32 {
			v = v[:32]
		}
		block, _ = aes.NewCipher([]byte(fmt.Sprintf("%-32v", v)))
	}

	cacheDir := buildCacheDir()

	return &DefaultCacheUtil{
		cacheDir:      cacheDir,
		tokenCacheDir: filepath.Join(cacheDir, "tokens"),
		vaultAPI:      vaultAPI,
		block:         block,
	}
}

// GetCacheDir returns the cache directory
func (c *DefaultCacheUtil) GetCacheDir() string {
	return c.cacheDir
}

// RenewToken attempts to renew a Vault client token. If successful, it will
// update the token's expiration date and write the file to disk ("cache"
// the token). If it fails, it will return an error.
func (c *DefaultCacheUtil) RenewToken(cached *CachedToken) error {
	var err error

	// Create a new Vault API client
	client := c.vaultAPI
	if client == nil {
		client, err = api.NewClient(nil)
		if err != nil {
			return err
		}
	}

	// Give the Vault API client the cached token
	client.SetToken(cached.Token)

	// Renew the token
	secret, err := client.Auth().Token().RenewSelf(0)
	if err != nil {
		return err
	}

	// Cache the token
	return c.CacheNewToken(secret, cached.AuthMethod)
}

// LookupToken attempts to retrieve a cached token that corresponds to the given
// method. It will search for both an encrypted and an unencrypted token in the
// token cache directory. If it finds an encrypted token (filename with no
// extension) first, it will decrypt it if $DOCKER_CREDS_CACHE_ENCRYPTION_KEY is
// set before JSON-decoding it. If it finds an unencrypted token (filename with
// .json extension), it will JSON-decode it without decryption. If no cached
// tokens are found, it will return a nil *CachedToken and a nil error.
func (c *DefaultCacheUtil) LookupToken(method config.VaultAuthMethod) (*CachedToken, error) {
	files, err := filepath.Glob(c.basename(method) + "*")
	if err != nil {
		return nil, err
	}

	mutex.RLock()
	defer mutex.RUnlock()

	for _, filename := range files {
		file, err := os.Open(filename)
		if err != nil {
			if os.IsNotExist(err) {
				// No token cache file found
				continue
			}
			return nil, err
		}

		data, err := ioutil.ReadAll(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		file.Close()

		// Decrypt if it is an encrypted file (encrypted file
		// should have no extension)
		if filepath.Ext(filename) == "" && c.block != nil {
			data, err = c.decrypt(data)
			if err != nil {
				return nil, fmt.Errorf("error decrypting token: %v", err)
			}
		}

		var cached = new(CachedToken)
		if err = jsonutil.DecodeJSON(data, cached); err != nil {
			return nil, fmt.Errorf("error JSON-decoding cached token %s: %v", filename, err)
		}
		cached.AuthMethod = method

		if cached.Token == "" {
			return nil, fmt.Errorf("no token found in cache file %s", filename)
		}

		return cached, nil
	}

	// No cached tokens found
	return nil, nil
}

// CacheNewToken accepts either a *CachedToken or a
// *github.com/hashicorp/vault/api.Secret and writes it to disk ("caches it")
// for use in future Vault API calls. If $DOCKER_CREDS_CACHE_ENCRYPTION_KEY is
// set, it will first encrypt the JSON data before caching it. If encryption is
// enabled, it will be cached with no file extension. Otherwise, it will be
// cached as a .json file. Tokens are cached according to the method of
// authentication by which it was obtained. For example, if a token was obtained
// using the "iam" method and encryption is disabled, it will be cached as:
//
// ~/.docker-credential-vault-login/tokens/cached-token-iam-auth.json
//
// If encryption is enabled, it will be cached as:
//
// ~/.docker-credential-vault-login/tokens/cached-token-iam-auth
//
func (c *DefaultCacheUtil) CacheNewToken(v interface{}, method config.VaultAuthMethod) error {
	var (
		token *CachedToken
		err   error
	)

	switch v.(type) {
	case *api.Secret:
		token, err = c.buildCachedTokenFromSecret(v.(*api.Secret), method)
		if err != nil {
			return fmt.Errorf("error creating cache.CachedToken instance from a *github.com/hashicorp/vault/api.Secret instance: %v", err)
		}
	case *CachedToken:
		token = v.(*CachedToken)
		if string(token.AuthMethod) == "" {
			token.AuthMethod = method
		}
	default:
		return fmt.Errorf("first argument passed to CacheNewToken not a unsupported type")
	}

	err = c.writeTokenToFile(token)
	if err != nil {
		return fmt.Errorf("error writing cache.CachedToken instance to disk: %v", err)
	}
	return nil
}

func (c *DefaultCacheUtil) buildCachedTokenFromSecret(secret *api.Secret,
	method config.VaultAuthMethod) (*CachedToken, error) {

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

	return &CachedToken{
		Token:      token,
		Expiration: expiration,
		Renewable:  renewable,
		AuthMethod: method,
	}, nil
}

func (c *DefaultCacheUtil) writeTokenToFile(token *CachedToken) error {
	// JSON-encode the CachedToken instance
	data, err := jsonutil.EncodeJSON(token)
	if err != nil {
		return err
	}

	// Encrypt if encryption is enabled
	if c.block != nil {
		data, err = c.encrypt(data)
		if err != nil {
			return fmt.Errorf("error encrypting token: %v", err)
		}
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Create the token cache directory and its parents
	// in case they don't already exist
	if err := os.MkdirAll(c.tokenCacheDir, 0765); err != nil {
		return err
	}

	// Open the cached token or create it if it
	// doesn't already exist
	file, err := os.OpenFile(c.TokenFilename(token.AuthMethod), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)

	return err
}

// ClearCachedToken deletes all cached tokens associated with the given
// authentication method.
func (c *DefaultCacheUtil) ClearCachedToken(method config.VaultAuthMethod) {
	files, _ := filepath.Glob(c.basename(method) + "*")
	mutex.Lock()
	for _, file := range files {
		os.Remove(file)
	}
	mutex.Unlock()
}

// TokenFilename returns the name of the file in which a token of the given
// authentication method is stored on disk. If $DOCKER_CREDS_CACHE_ENCRYPTION_KEY
// is set (i.e. encryption is enabled), it will return a filename with no
// extension. Otherwise, it will return a filename with a .json extension.
func (c *DefaultCacheUtil) TokenFilename(method config.VaultAuthMethod) string {
	extension := ".json"

	// If the file is encrypted, do not include a file extension
	if c.block != nil {
		extension = ""
	}
	return c.basename(method) + extension
}

func (c *DefaultCacheUtil) encrypt(data []byte) ([]byte, error) {
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(c.block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func (c *DefaultCacheUtil) decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

func (c *DefaultCacheUtil) basename(method config.VaultAuthMethod) string {
	return filepath.Join(c.tokenCacheDir, "cached-token-"+string(method)+"-auth")
}

// NullCacheUtil conforms to the CacheUtil interface
// and implements stub functions (with the exception of
// GetCacheDir()). It is primarily for testing purposes
type NullCacheUtil struct {
	cacheDir string
}

// NewNullCacheUtil creates a new CacheUtil object. The value of
// its cacheDir field is set to the value of the
// DOCKER_CREDS_CACHE_DIR environment variable if it is set.
// Otherwise, it uses the default directory.
func NewNullCacheUtil() *NullCacheUtil {
	return &NullCacheUtil{buildCacheDir()}
}

func (n *NullCacheUtil) GetCacheDir() string {
	return n.cacheDir
}

func (n *NullCacheUtil) LookupToken(method config.VaultAuthMethod) (*CachedToken, error) {
	return nil, nil
}

func (n *NullCacheUtil) CacheNewToken(v interface{}, method config.VaultAuthMethod) error {
	return nil
}

func (n *NullCacheUtil) ClearCachedToken(method config.VaultAuthMethod) {
	return
}

func (n *NullCacheUtil) RenewToken(token *CachedToken) error {
	return nil
}

func (n *NullCacheUtil) TokenFilename(method config.VaultAuthMethod) string {
	return ""
}

func buildCacheDir() string {
	var cacheDirRaw = DefaultCacheDir
	if v := os.Getenv(EnvCacheDir); v != "" {
		cacheDirRaw = v
	}

	cacheDir, err := homedir.Expand(cacheDirRaw)
	if err != nil {
		fmt.Printf("Failed to create cache file at %s.\nCreating log file at %s instead.\n",
			cacheDirRaw, BackupCacheDir)
		cacheDir = BackupCacheDir
	}

	return filepath.Clean(cacheDir)
}
