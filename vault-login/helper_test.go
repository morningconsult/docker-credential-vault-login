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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"

	logger "github.com/morningconsult/docker-credential-vault-login/vault-login/cache/logging"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

const (
	EnvAWSAccessKeyID string = "AWS_ACCESS_KEY_ID"

	EnvAWSAccessKey string = "AWS_ACCESS_KEY"

	EnvAWSSecretAccessKey string = "AWS_SECRET_ACCESS_KEY"

	EnvAWSSecretKey string = "AWS_SECRET_KEY"

	TestAccessKey string = "AKIAIJWPJLKME2OBDB6Q"

	TestSecretKey string = "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"
)

var (
	testConfigFilename  string = filepath.Join("testdata", "shared_config")
	testIAMConfigFile   string = filepath.Join("testdata", "config_iam.json")
	testEC2ConfigFile   string = filepath.Join("testdata", "config_ec2.json")
	testTokenConfigFile string = filepath.Join("testdata", "config_token.json")
)

func TestHelperGet_IAM_Success(t *testing.T) {
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

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	helper := NewHelper(nil)
	user, pw, err := helper.Get("")
	if err != nil {
		t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
	}
	if v, _ := opts.Secret["username"].(string); v != user {
		t.Errorf("Expected username %q, got %q", v, user)
	}
	if v, _ := opts.Secret["password"].(string); v != pw {
		t.Errorf("Expected password %q, got %q", v, pw)
	}
}

// TestHelperGet_IAM_BadPath tests that when a user does not provide
// the path to their Docker credentials in the "secret_path"
// field of the config.json file, the helper.Get() method returns
// an error
func TestHelperGet_IAM_BadPath(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			// secretPath delibarately does not match the "secret_path" field
			// of the config.json file in order to cause an error -- this is the
			// purpose of this unit test
			SecretPath: "secret/bim/baz",
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Role,
		}
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Errorf("should have returned and error, but didn't.")
	}
}

// TestHelperGet_IAM_NoSecret tests that when a user provides the path
// to their Docker credentials in the "secret_path" field of
// the config.json file but no credentials are present at that location,
// the helper.Get() method returns an error.
func TestHelperGet_IAM_NoSecret(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			// secret is initialized with no data so that when the helper
			// attempts to read the secret at secretPath, it will get
			// no data, and then return an error
			Secret: map[string]interface{}{},
			Role:   cfg.Role,
		}
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Errorf("should have returned and error, but didn't.")
	}
}

// TestHelperGet_IAM_BadRole tests that when a user provides a Vault role
// in the "role" field of the config.json file that has not been
// configured with the IAM role used to authenticate againt AWS,
// the helper.Get() method returns an error.
func TestHelperGet_IAM_BadRole(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret:     map[string]interface{}{},
			Role:       "fake-role",
		}
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Errorf("should have returned and error, but didn't.")
	}
}

// TestHelperGet_IAM_MalformedSecret tests that when the Vault secret
// representing the Docker credentials is not properly formatted,
// the helper.Get() method returns an error. Note that this program
// expects the Docker credentials to be stored in Vault as follows:
// {
//      "username": "docker_user",
//      "password": "password"
// }
func TestHelperGet_IAM_MalformedSecret(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				// Expects field to be spelled "username"
				"usename":  "docker@user.com",
				"password": "potato",
			},
			Role: "fake-role",
		}
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Errorf("should have returned and error, but didn't.")
	}
}

func TestHelperGet_IAM_FactoryError(t *testing.T) {
	var testConfigFile = testIAMConfigFile

	// Backwards compatibility with Shared config disabled
	// assume role should not be built into the config.
	os.Setenv("AWS_CONFIG_FILE", "file_not_exists")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "file_not_exists")
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", testConfigFilename)
	os.Setenv("AWS_PROFILE", "assume_role_invalid_source_profile")

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("should have returned and error, but didn't.")
	}

	os.Unsetenv("AWS_CONFIG_FILE")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_SDK_LOAD_CONFIG")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_PROFILE")

	test.ErrorsEqual(t, err.Error(), credentials.NewErrCredentialsNotFound().Error())
}

func TestHelperGet_EC2_FactoryError(t *testing.T) {
	var testConfigFile = testEC2ConfigFile

	// Backwards compatibility with Shared config disabled
	// assume role should not be built into the config.
	os.Setenv("AWS_CONFIG_FILE", "file_not_exists")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "file_not_exists")
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", testConfigFilename)
	os.Setenv("AWS_PROFILE", "assume_role_invalid_source_profile")

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("should have returned and error, but didn't.")
	}

	os.Unsetenv("AWS_CONFIG_FILE")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_SDK_LOAD_CONFIG")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_PROFILE")

	test.ErrorsEqual(t, err.Error(), credentials.NewErrCredentialsNotFound().Error())
}

func TestHelperGet_Token(t *testing.T) {
	var (
		testConfigFile = testTokenConfigFile
		cfg            = readConfig(t, testConfigFile)
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := test.NewPreConfiguredVaultClient(t, cluster)

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	// Set VAULT_TOKEN environment variable to the token already
	// assigned to the client (to conform with ClientFactory behavior)
	os.Setenv(api.EnvVaultToken, client.Token())

	cases := []struct{
		name       string
		actualPath string
		secret     map[string]interface{}
		err        bool
	}{
		{
			"success",
			cfg.Secret,
			map[string]interface{}{
				"username": "frodo.baggins@theshire.com",
				"password": "potato",
			},
			false,
		},
		{
			"bad-path",
			// Differs from path at which secret was written per
			// the config.json file
			"secret/bim/baz",
			map[string]interface{}{
				"username": "frodo.baggins@theshire.com",
				"password": "potato",
			},
			true,
		},
		{
			"malformed-secret",
			cfg.Secret,
			map[string]interface{}{
				// Malformed "username" field
				"usename":  "frodo.baggins@theshire.com",
				"password": "potato",
			},
			true,
		},
		{
			"bad-client",
			cfg.Secret,
			map[string]interface{}{
				// Malformed "username" field
				"username":  "frodo.baggins@theshire.com",
				"password": "potato",
			},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Write the secret to the test cluster
			test.WriteSecret(t, client, tc.actualPath, tc.secret)
			defer test.DeleteSecret(t, client, tc.actualPath)

			var helper *Helper
			if tc.name == "bad-client" {
				os.Setenv(api.EnvRateLimit, "not an int!")
				defer os.Unsetenv(api.EnvRateLimit)
				helper = NewHelper(nil)
			} else {
				helper = NewHelper(&HelperOptions{
					VaultClient: client,
				})
			}

			user, pw, err := helper.Get("")
			
			if tc.err {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if username, ok := tc.secret["username"].(string); !ok || username != user {
				t.Fatalf("Wrong username (got %q, expected %q)", user, username)
			}
			if password, ok := tc.secret["password"].(string); !ok || password != pw {
				t.Fatalf("Wrong password (got %q, expected %q)", pw, password)
			}
		})
	}
}


func TestHelperGet_Token_NoTokenEnv(t *testing.T) {
	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testTokenConfigFile)
	token := os.Getenv(api.EnvVaultToken)
	os.Unsetenv(api.EnvVaultToken)
	defer os.Setenv(api.EnvVaultToken, token)

	helper := NewHelper(nil)

	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestHelperList(t *testing.T) {
	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	helper := NewHelper(nil)
	_, err := helper.List()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), notImplementedError.Error())
}

func TestHelperAdd(t *testing.T) {
	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	helper := NewHelper(nil)
	err := helper.Add(&credentials.Credentials{})
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), notImplementedError.Error())
}

func TestHelperDelete(t *testing.T) {
	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	helper := NewHelper(nil)
	err := helper.Delete("")
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), notImplementedError.Error())
}

// TestHelperGet_ParseError test that when helper.Get() is called
// but the config.json file is improperly formatted (and thus
// cannot be decoded) the correct error is returned.
func TestHelperGet_ParseError(t *testing.T) {
	const testFilePath = "/tmp/docker-credential-vault-login-testfile.json"

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	data := test.EncodeJSON(t, map[string]int{"foo": 1234})
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	os.Setenv("DOCKER_CREDS_CONFIG_FILE", testFilePath)

	helper := NewHelper(nil)
	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), credentials.NewErrCredentialsNotFound().Error())
}


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

func TestMain(m *testing.M) {
	path := os.Getenv("PATH")
	env := awstesting.StashEnv()

	// PATH must be set because awstesting.StashEnv()
	// unsets the value of $PATH and homedir.Expand()
	// requires the $PATH to execute the "sh" command
	os.Setenv("PATH", path)

	defer awstesting.PopEnv(env)
	defer seelog.Flush()
	logger.SetupTestLogger()
	os.Exit(m.Run())
}

func readConfig(t *testing.T, testConfigFile string) *config.CredHelperConfig {
	data, err := ioutil.ReadFile(testConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	var cfg = new(config.CredHelperConfig)
	if err = json.Unmarshal(data, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}
