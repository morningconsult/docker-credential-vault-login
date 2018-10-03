package cache

import (
	"fmt"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultTokenTTL int64  = 86400 // 1 day
	EnvCacheDir     string = "DOCKER_CREDS_CACHE_DIR"
	EnvDisableCache string = "DOCKER_CREDS_DISABLE_CACHE"
	EnvTokenTTL     string = "DOCKER_CREDS_TOKEN_TTL"
	DefaultCacheDir string = "~/.docker-credential-vault-login"
	BackupCacheDir  string = "/tmp/.docker-credential-vault-login"
)

var mutex sync.RWMutex

type CacheUtil interface {
	GetCacheDir() string
	GetCachedToken(config.VaultAuthMethod) (*CachedToken, error)
	CacheNewToken(*api.Secret, config.VaultAuthMethod) error
	ClearCachedToken(config.VaultAuthMethod)
	RenewToken(*CachedToken) error
}

// NewCacheUtil returns a new NullCacheUtil if the
// DOCKER_CREDS_DISABLE_CACHE environment variable is set.
// Otherwise, it returns a new DefaultCacheUtil.
func NewCacheUtil() CacheUtil {
	if os.Getenv(EnvDisableCache) != "" {
		return NewNullCacheUtil()
	}
	return NewDefaultCacheUtil()
}

type DefaultCacheUtil struct {
	cacheDir      string
	tokenCacheDir string
	tokenTTL      int64
}

// NewDefaultCacheUtil creates a new CacheUtil object. The value of
// its cacheDir field is set to the value of the
// DOCKER_CREDS_CACHE_DIR environment variable if it is set.
// Otherwise, it uses the default directory.
func NewDefaultCacheUtil() *DefaultCacheUtil {
	cacheDir := buildCacheDir()

	var ttl int64 = DefaultTokenTTL
	if v := os.Getenv(EnvTokenTTL); v != "" {
		if i, err := strconv.ParseInt(v, 10, 32); err == nil {
			ttl = i
		}
	}

	return &DefaultCacheUtil{
		cacheDir:      cacheDir,
		tokenCacheDir: filepath.Join(cacheDir, "tokens"),
		tokenTTL:      ttl,
	}
}

func (c *DefaultCacheUtil) GetCacheDir() string {
	return c.cacheDir
}

func (c *DefaultCacheUtil) RenewToken(cached *CachedToken) error {
	// Create a new Vault API client
	client, err := api.NewClient(nil)
	if err != nil {
		return err
	}

	// Give the Vault API client the cached token
	client.SetToken(cached.Token)

	// Renew the token
	secret, err := client.Auth().Token().Renew(cached.Token, int(c.tokenTTL))
	if err != nil {
		return err
	}

	// Cache the token
	return c.CacheNewToken(secret, cached.AuthMethod)
}

func (c *DefaultCacheUtil) GetCachedToken(method config.VaultAuthMethod) (*CachedToken, error) {
	mutex.RLock()
	defer mutex.RUnlock()

	fname := c.tokenFilename(method)
	file, err := os.Open(fname)
	if err != nil {
		if os.IsNotExist(err) {
			// No toke cache file found
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var cached = new(CachedToken)
	if err = jsonutil.DecodeJSONFromReader(file, cached); err != nil {
		return nil, fmt.Errorf("error JSON-decoding token cache file %s: %v", fname, err)
	}
	cached.AuthMethod = method

	if cached.Token == "" {
		return nil, fmt.Errorf("no token found in cache file %s", fname)
	}

	if _, err = uuid.ParseUUID(cached.Token); err != nil {
		return nil, fmt.Errorf("token found in cache file %s is not a valid UUID", fname)
	}

	return cached, nil
}

func (c *DefaultCacheUtil) CacheNewToken(secret *api.Secret, method config.VaultAuthMethod) error {
	// Get the token from the secret
	token, err := secret.TokenID()
	if err != nil {
		return err
	}

	// Get the token's TTL
	ttl, err := secret.TokenTTL()
	if err != nil {
		return err
	}
	expiration := time.Now().Add(time.Second * ttl).Unix()

	// Get the token's renewability
	renewable, err := secret.TokenIsRenewable()
	if err != nil {
		return err
	}

	data, err := jsonutil.EncodeJSON(&CachedToken{
		Token:      token,
		Expiration: expiration,
		Renewable:  renewable,
	})
	if err != nil {
		return err
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Create the token cache directory and its parents
	// in case they don't already exist
	if err := os.MkdirAll(c.tokenCacheDir, 0755); err != nil {
		return err
	}

	// Open the token cache file or create it if it
	// doesn't already exist
	file, err := os.OpenFile(c.tokenFilename(method), os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)

	return err
}

func (c *DefaultCacheUtil) ClearCachedToken(method config.VaultAuthMethod) {
	mutex.Lock()
	os.Remove(c.tokenFilename(method))
	mutex.Unlock()
}

func (c *DefaultCacheUtil) tokenFilename(method config.VaultAuthMethod) string {
	return filepath.Join(c.tokenCacheDir, "cached-token-"+string(method)+"-auth.json")
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
	cacheDir := buildCacheDir()
	return &NullCacheUtil{cacheDir}
}

func (n *NullCacheUtil) GetCacheDir() string {
	return n.cacheDir
}

func (n *NullCacheUtil) GetCachedToken(method config.VaultAuthMethod) (*CachedToken, error) {
	return nil, nil
}

func (n *NullCacheUtil) CacheNewToken(secret *api.Secret, method config.VaultAuthMethod) error {
	return nil
}

func (n *NullCacheUtil) ClearCachedToken(method config.VaultAuthMethod) {
	return
}

func (n *NullCacheUtil) RenewToken(token *CachedToken) error {
	return nil
}

func buildCacheDir() string {
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

	return filepath.Clean(cacheDir)
}
