package cache

import (
        "path/filepath"
        "fmt"
	"log"
        "os"
        "time"
        uuid "github.com/hashicorp/go-uuid"
        "github.com/hashicorp/vault/helper/jsonutil"
        homedir "github.com/mitchellh/go-homedir"
        "github.com/morningconsult/docker-credential-vault-login/vault-login/config"
)

const (
        EnvCacheDir     string = "DOCKER_CREDS_CACHE_DIR"
        EnvDisableCache string = "DOCKER_CREDS_DISABLE_CACHE"
	DefaultCacheDir string = "~/.docker-credential-vault-login"
	BackupCacheDir  string = "/tmp/.docker-credential-vault-login"
)

type CachedToken struct {
        // The cached Vault token
        Token string `json:"token"`

        // The date and time at which this token expires
        // (represented as a Unix timestamp).
        Expiration int64 `json:"expiration"`
}

type CacheUtil interface {
        GetCacheDir() string
        GetCachedToken(config.VaultAuthMethod) (string, error)
        CacheNewToken(string, int, config.VaultAuthMethod) error
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
}

// NewDefaultCacheUtil creates a new CacheUtil object. The value of
// its cacheDir field is set to the value of the
// DOCKER_CREDS_CACHE_DIR environment variable if it is set.
// Otherwise, it uses the default directory.
func NewDefaultCacheUtil() CacheUtil {
	cacheDir := buildCacheDir()

	return &DefaultCacheUtil{
                cacheDir:      cacheDir,
                tokenCacheDir: filepath.Join(cacheDir, "tokens"),
        }
}

func (c *DefaultCacheUtil) GetCacheDir() string {
	return c.cacheDir
}

func (c *DefaultCacheUtil) GetCachedToken(method config.VaultAuthMethod) (string, error) {
        file, err := os.Open(c.tokenFilename(method))
        if err != nil {
                if os.IsNotExist(err) {
                        return "", nil
                }
                return "", err
        }
        defer file.Close()

        var cached = new(CachedToken)
        if err = jsonutil.DecodeJSONFromReader(file, cached); err != nil {
                return "", err
        }

        // Convert Unix expiration timestamp to time.Time
        expires := time.Unix(cached.Expiration, 0)

        // If the token expires a minute or sooner from now,
        // don't return the cached token
        if time.Now().Add(time.Minute * 1).After(expires) {
                return "", nil
        }

        // If the token expires more than a minute from now,
        // ensure that cached.Token is a UUID and return the
        // cached token if it is indeed valid
        if _, err = uuid.ParseUUID(cached.Token); err != nil {
                return "", fmt.Errorf("Cached token %q is not a valid UUID", cached.Token)
        }
        return cached.Token, nil
}

func (c *DefaultCacheUtil) CacheNewToken(token string, ttl int, method config.VaultAuthMethod) error {
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

        // Create the expiration date as a Unix timestamp
        expiration := time.Now().Add(time.Second * time.Duration(ttl)).Unix()

        data, err := jsonutil.EncodeJSON(&CachedToken{
                Token:      token,
                Expiration: expiration,
        })
        if err != nil {
                return err
        }

        if _, err = file.Write(data); err != nil {
                return err
        }

        return nil
}

func (c *DefaultCacheUtil) tokenFilename(method config.VaultAuthMethod) string {
        return filepath.Join(c.tokenCacheDir, "cached-token-" + string(method) + "-auth.json")
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
func NewNullCacheUtil() CacheUtil {
	cacheDir := buildCacheDir()
	return &NullCacheUtil{cacheDir}
}

func (n *NullCacheUtil) GetCacheDir() string {
        return n.cacheDir
}

func (n *NullCacheUtil) GetCachedToken(method config.VaultAuthMethod) (string, error) {
        return "", nil
}

func (n *NullCacheUtil) CacheNewToken(token string, ttl int, method config.VaultAuthMethod) error {
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
