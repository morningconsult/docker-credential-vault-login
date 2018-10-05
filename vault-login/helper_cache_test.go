package helper

import (
	"path/filepath"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

func TestHelperGet_MalformedToken(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Role,
		}
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	cacheUtil := cache.NewCacheUtil(nil)

	tokenfile := cacheUtil.TokenFilename(cfg.Method)

	// Write a malformed token to file
	var badtoken = "i am not a token"
	json := map[string]interface{}{
		"token":      badtoken,
		"expiration": "not an int!",
	}
	writeJSONToFile(t, json, tokenfile)

	helper := NewHelper(&HelperOptions{
		CacheUtil: cacheUtil,
	})

	_, _, err := helper.Get("")
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that a new, properly-formatted token was cached
	token := loadTokenFromFile(t, tokenfile)

	// Ensure that a new token was obtained
	if token.Token == badtoken {
		t.Fatal("should have obtained a new token but didn't")
	}

	// Ensure that the token is not expired
	if token.Expired() {
		t.Fatal("did not expect token to be expired but it was")
	}
}

func TestHelperGet_NoToken(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Role,
		}
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	cacheUtil := cache.NewCacheUtil(nil)

	tokenfile := cacheUtil.TokenFilename(cfg.Method)

	// Delete the cached token (if exists)
	cacheUtil.ClearCachedToken(cfg.Method)

	helper := NewHelper(&HelperOptions{
		CacheUtil: cacheUtil,
	})

	_, _, err := helper.Get("")
	if err != nil {
		t.Fatal(err)
	}

	// Ensure that a new, properly-formatted token was cached
	token := loadTokenFromFile(t, tokenfile)

	// Ensure that a new token was obtained
	if token.Token == "" {
		t.Fatal("should have obtained a new token but didn't")
	}

	// Ensure that the token is not expired
	if token.Expired() {
		t.Fatal("did not expect token to be expired but it was")
	}
}

// Tests that 
func TestHelperGet_RenewableToken(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		secret         = map[string]interface{}{
			"username": "frodo.baggins@shire.com",
			"password": "potato",
		}
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	cacheUtil := cache.NewCacheUtil(nil)

	// Start test Vault cluster
	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()
	client := test.NewPreConfiguredVaultClient(t, cluster)
	rootToken := client.Token()

	// Write the secret to Vault at the endpoint
	// given in config.json
	test.WriteSecret(t, client, cfg.Secret, secret)

	// Create the test policy
	var testPolicy = "dev-test"
	policy := `path "`+cfg.Secret+`" {
		capabilities = ["read", "list"]
	}`
	err := client.Sys().PutPolicy(testPolicy, policy)
	if err != nil {
		t.Fatal(err)
	}

	tsRenewable := time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds / 2)).Unix()
	cases := []struct{
		name       string
		expiration int64
		comparison string
	}{
		{
			"renew",
			tsRenewable,
			"gt",
		},
		{
			"no-renew",
			time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds * 2)).Unix(),
			"eq",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Make sure that at this point the client has
			// the root token
			client.SetToken(rootToken)

			// Create a new token for the policy
			resp, err := client.Logical().Write(filepath.Join("auth", "token", "create"), map[string]interface{}{
				"policies": []string{testPolicy},
			})
			if err != nil {
				t.Fatal(err)
			}

			// Get token from response
			token, err := resp.TokenID()
			if err != nil {
				t.Fatal(err)
			}

			// Give the newly-created, non-root client token
			// to the Vault API client
			client.SetToken(token)

			helper := NewHelper(&HelperOptions{
				VaultClient: client,
			})

			// Delete the cached token (if exists)
			cacheUtil.ClearCachedToken(cfg.Method)

			// Cache the token
			err = cacheUtil.CacheNewToken(&cache.CachedToken{
				Token:      token,
				Expiration: tc.expiration,
				Renewable:  true,
			}, cfg.Method)
			if err != nil {
				t.Fatal(err)
			}

			// Sleep for a couple seconds so that the next time
			// time.Now().Unix() is called a different value
			// is returned
			time.Sleep(2 * time.Second)

			// Execute helper.Get(""), the function being tested
			user, pw, err := helper.Get("")
			if err != nil {
				t.Fatal(err)
			}

			defer cacheUtil.ClearCachedToken(cfg.Method)

			// Check that the secret was successfully read
			if username, ok := secret["username"].(string); !ok || username != user {
				t.Fatalf("Wrong username (got %q, expected %q)", user, username)
			}
			if password, ok := secret["password"].(string); !ok || password != pw {
				t.Fatalf("Wrong password (got %q, expected %q)", pw, password)
			}

			cachedToken, err := cacheUtil.GetCachedToken(cfg.Method)
			if err != nil {
				t.Fatal(err)
			}

			switch tc.comparison {
			case "gt":
				if cachedToken.Expiration <= tc.expiration {
					t.Fatal("when the cached token was renewed it should have increased the expiration date")
				}
			case "eq":
				if cachedToken.Expiration != tc.expiration {
					t.Fatal("the expiration date of the cached token should not have changed")
				}
			}
		})
	}
}

func TestHelperGet_CantUseCachedToken(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Role,
		}
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")
	cacheUtil := cache.NewCacheUtil(nil)

	// Spin up mock Vault server
	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)
	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	// var badtoken = "i am not a token"

	cases := []struct {
		name       string
		expiration int64
		renewable  bool
	}{
		{
			"renew-fails",
			time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds / 2)).Unix(),
			true,
		},
		{
			"expired",
			time.Now().Add(-10 * time.Hour).Unix(),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var badtoken = "i am a bad token"

			cacheUtil.ClearCachedToken(cfg.Method)			
			defer cacheUtil.ClearCachedToken(cfg.Method)
			writeJSONToFile(t, map[string]interface{}{
				"token":      badtoken, // this should trigger an error when CacheUtil.RenewToken() is called
				"expiration": tc.expiration,
				"renewable":  tc.renewable,
			}, cacheUtil.TokenFilename(cfg.Method))

			helper := NewHelper(&HelperOptions{
				CacheUtil: cacheUtil,
			})

			_, _, err := helper.Get("")
			if err != nil {
				t.Fatal(err)
			}
			
			token := loadTokenFromFile(t, cacheUtil.TokenFilename(cfg.Method))

			// Ensure that a new token was obtained
			if token.Token == badtoken {
				t.Fatal("should have obtained a new token but didn't")
			}

			// Ensure that the expiration date is in the future
			if time.Unix(token.Expiration, 0).Before(time.Now()) {
				t.Fatal("cached token should not be expired")
			}
		})
	}
}

func TestHelperGet_NewClientFails(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")
	cacheUtil := cache.NewCacheUtil(nil)

	cacheUtil.ClearCachedToken(cfg.Method)			
	defer cacheUtil.ClearCachedToken(cfg.Method)
	writeJSONToFile(t, map[string]interface{}{
		"token":      "token",
		"expiration": time.Now().Add(1 * time.Hour).Unix(),
		"renewable":  false,
	}, cacheUtil.TokenFilename(cfg.Method))

	os.Setenv(api.EnvRateLimit, "not an int!")
	defer os.Unsetenv(api.EnvRateLimit)

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestHelperGet_CachedTokenUnauthorized(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Role,
		}
	)

	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, "testdata")
	cacheUtil := cache.NewCacheUtil(nil)

	// Spin up mock Vault server
	server, token := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	cacheUtil.ClearCachedToken(cfg.Method)			
	defer cacheUtil.ClearCachedToken(cfg.Method)
	writeJSONToFile(t, map[string]interface{}{
		"token":      "bad token",
		"expiration": time.Now().Add(1 * time.Hour).Unix(),
		"renewable":  false,
	}, cacheUtil.TokenFilename(cfg.Method))

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAddress(fmt.Sprintf("http://127.0.0.1%s", server.Addr))
	helper := NewHelper(&HelperOptions{
		VaultClient: client,
	})
	_, _, err = helper.Get("")
	if err != nil {
		t.Fatal(err)
	}

	// Should cache the token returned during authentication
	cachedToken := loadTokenFromFile(t, cacheUtil.TokenFilename(cfg.Method))
	if cachedToken.Token != token {
		t.Fatalf("expected cached token ID %q, but got %q instead", token, cachedToken.Token)
	}
}

func writeJSONToFile(t *testing.T, json map[string]interface{}, tokenfile string) {
	data, err := jsonutil.EncodeJSON(json)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(tokenfile), 0755); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(tokenfile, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		t.Fatal(err)
	}
}

func loadTokenFromFile(t *testing.T, filename string) *cache.CachedToken {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var token = new(cache.CachedToken)
	if err = jsonutil.DecodeJSONFromReader(file, token); err != nil {
		t.Fatal(err)
	}
	return token
}
