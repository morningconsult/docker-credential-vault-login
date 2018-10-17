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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/mitchellh/mapstructure"

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

const testDataDir string = "testdata"

var (
	testConfigFilename  string = filepath.Join(testDataDir, "shared_config")
	testIAMConfigFile   string = filepath.Join(testDataDir, "config_iam.json")
	testEC2ConfigFile   string = filepath.Join(testDataDir, "config_ec2.json")
	testTokenConfigFile string = filepath.Join(testDataDir, "config_token.json")
)

// var testConfigFileWithVaultClientConfig string = filepath.Join(testDataDir, "config_client.json")

func TestHelperGet_ErrCreateClient(t *testing.T) {
	rl := os.Getenv(api.EnvRateLimit)

	// This will trigger an error when github.com/hashicorp/vault/api.NewClient()
	// is called
	os.Setenv(api.EnvRateLimit, "not an int!")
	defer os.Setenv(api.EnvRateLimit, rl)

	os.Setenv(config.EnvConfigFilePath, testTokenConfigFile)
	helper := NewHelper(nil)

	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("expected an error")
	}
}

// TestHelperGet_ClientConfig tests that if Vault client configuration
// parameters are specified in the config.json file, it will use them
// to configure the Vault client
func TestHelperGet_ClientConfig(t *testing.T) {
	testFilePath := filepath.Join("testdata", "config_client_test.json")
	vaultEnvVars := []string{
		api.EnvVaultAddress,
		api.EnvVaultToken,
		api.EnvVaultCACert,
		api.EnvVaultClientCert,
		api.EnvVaultClientKey,
		api.EnvVaultTLSServerName,
	}
	
	for _, env := range vaultEnvVars {
		os.Unsetenv(env)
	}

	const vaultAddr = "https://vault.service.consul"

	cfg := &config.CredHelperConfig{
		Auth: config.AuthConfig{
			Method: "token",
		},
		Client: map[string]string{
			"vault_addr":            vaultAddr,
			"vault_cacert":          filepath.Join("testdata", "vault-ca.pem"),
			"vault_client_cert":     filepath.Join("testdata", "client.pem"),
			"vault_client_key":      filepath.Join("testdata", "client-key.pem"),
			"vault_tls_server_name": "my.server.name",
		},
		Secret: "secret/foo/bar",
	}
	data, err := jsonutil.EncodeJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)
	os.Setenv(config.EnvConfigFilePath, testFilePath)

	helper := NewHelper(nil)
	helper.Get("")
	if helper.VaultClient() == nil {
		t.Fatal("no Vault client was created")
	}
	if helper.VaultClient().Address() != vaultAddr {
		t.Fatalf("expected Vault client address to be %q but got %q", vaultAddr, helper.VaultClient().Address())
	}

	for _, env := range vaultEnvVars {
		if os.Getenv(env) != "" {
			t.Fatalf("expected $%s to be unset", env)
		}
	}
}

func TestHelperGet_AWS(t *testing.T) {
	var (
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
	)

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	// Set AWS credential environment variables
	test.SetTestAWSEnvVars()

	cases := []struct {
		name       string
		secretPath string
		secret     map[string]interface{}
		role       string
		err        bool
	}{
		{
			"success",
			cfg.Secret,
			map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			cfg.Auth.Role,
			false,
		},
		{
			"no-secret",
			cfg.Secret,
			map[string]interface{}{},
			cfg.Auth.Role,
			true,
		},
		{
			"bad-path",
			// path is different from the secret_path in the config.json file
			"secret/bim/baz",
			map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			cfg.Auth.Role,
			true,
		},
		{
			"bad-role",
			cfg.Secret,
			map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			// role has not been configured to login via aws auth
			"bad role",
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{
				SecretPath: tc.secretPath,
				Secret:     tc.secret,
				Role:       tc.role,
			})
			go server.ListenAndServe()
			defer server.Close()

			os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1%s", server.Addr))

			helper := NewHelper(nil)

			_, _, err := helper.Get("")

			if tc.err && (err == nil) {
				t.Fatal("should have returned and error, but didn't.")
			}

			if !tc.err && (err != nil) {
				t.Fatal("should not have returned an error")
			}
		})
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

	cases := []struct {
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
			"no-token",
			cfg.Secret,
			map[string]interface{}{
				"username": "frodo.baggins@theshire.com",
				"password": "potato",
			},
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Write the secret to the test cluster
			test.WriteSecret(t, client, tc.actualPath, tc.secret)
			defer test.DeleteSecret(t, client, tc.actualPath)

			helper := NewHelper(&HelperOptions{
				VaultAPI: client,
			})

			if tc.name == "no-token" {
				rootToken := client.Token()
				defer client.SetToken(rootToken)

				// Should get the token from the environment if not set
				client.ClearToken()
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

	// If you select the "token" auth method, the VAULT_TOKEN 
	// environmental varaible must be set or it will throw an error
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
	const testFilePath = "testdata/docker-credential-vault-login-testfile.json"

	// Disable caching
	os.Setenv(cache.EnvDisableCache, "true")

	data := test.EncodeJSON(t, map[string]int{"foo": 1234})
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	os.Setenv(config.EnvConfigFilePath, testFilePath)
	defer os.Unsetenv(config.EnvConfigFilePath)

	helper := NewHelper(nil)

	_, _, err := helper.Get("")
	if err == nil {
		t.Fatal("expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), credentials.NewErrCredentialsNotFound().Error())
}

func TestHelperGet_RenewableToken(t *testing.T) {
	var (
		cacheDir       = testDataDir
		testConfigFile = testIAMConfigFile
		tokenFilename  = filepath.Join(cacheDir, "tokens.json")
		cfg            = readConfig(t, testConfigFile)
		secret         = map[string]interface{}{
			"username": "frodo.baggins@shire.com",
			"password": "potato",
		}
	)

	// Enable caching
	os.Unsetenv(cache.EnvDisableCache)

	// This tests that the cache.dir field of the config.json file
	// gets passed to CacheUtil
	os.Unsetenv(cache.EnvCacheDir)

	os.Setenv(config.EnvConfigFilePath, testConfigFile)

	// Start test Vault cluster
	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()
	client := test.NewPreConfiguredVaultClient(t, cluster)
	rootToken := client.Token()

	addr := client.Address()
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}

	host := u.Host

	// Write the secret to Vault at the endpoint
	// given in config.json
	test.WriteSecret(t, client, cfg.Secret, secret)

	// Create the test policy
	var testPolicy = "dev-test"
	policy := `path "` + cfg.Secret + `" {
		capabilities = ["read", "list"]
	}`
	err = client.Sys().PutPolicy(testPolicy, policy)
	if err != nil {
		t.Fatal(err)
	}

	tsRenewable := time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds/2)).Unix()
	cases := []struct {
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
			time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds*2)).Unix(),
			"eq",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			client.ClearToken()

			helper := NewHelper(&HelperOptions{
				VaultAPI: client,
			})

			// Delete the cached token (if exists)
			clearTestdata(cacheDir)
			defer clearTestdata(cacheDir)

			// Cache the token
			tokenFile := map[string]interface{}{
				host: map[string]interface{}{
					string(cfg.Auth.Method): map[string]interface{}{
						"token":      token,
						"expiration": tc.expiration,
						"renewable":  true,
					},
				},
			}
			writeTokenFile(t, tokenFile, tokenFilename)

			// Sleep for a couple seconds so that the next time
			// time.Now().Unix() is called a different value
			// is returned
			time.Sleep(2 * time.Second)

			// Execute helper.Get(""), the function being tested
			user, pw, err := helper.Get("")
			if err != nil {
				t.Fatal(err)
			}

			// Check that the secret was successfully read
			if username, ok := secret["username"].(string); !ok || username != user {
				t.Fatalf("Wrong username (got %q, expected %q)", user, username)
			}
			if password, ok := secret["password"].(string); !ok || password != pw {
				t.Fatalf("Wrong password (got %q, expected %q)", pw, password)
			}

			cachedToken := loadTokenFromFile(t, tokenFilename, addr, cfg.Auth.Method)

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
		cacheDir       = testDataDir
		badtoken       = "i am not a token"
		testConfigFile = testIAMConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &test.TestVaultServerOptions{
			SecretPath: cfg.Secret,
			Secret: map[string]interface{}{
				"username": "frodo.baggins@shire.com",
				"password": "potato",
			},
			Role: cfg.Auth.Role,
		}
	)

	test.SetTestAWSEnvVars()
	os.Unsetenv(cache.EnvDisableCache)
	os.Setenv(cache.EnvCacheDir, cacheDir)

	cacheUtil := cache.NewCacheUtil(cacheDir, false)

	// Spin up mock Vault server
	server, _ := test.MakeMockVaultServerIAMAuth(t, opts)
	go server.ListenAndServe()
	defer server.Close()

	addr := fmt.Sprintf("http://127.0.0.1%s", server.Addr)
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	// Set the environment variable informing the program where
	// the config.json file is located
	os.Setenv(config.EnvConfigFilePath, testConfigFile)
	os.Setenv(api.EnvVaultAddress, addr)

	cases := []struct {
		name string
		file map[string]interface{}
	}{
		{
			"renew-fails",
			map[string]interface{}{
				host: map[string]interface{}{
					string(cfg.Auth.Method): map[string]interface{}{
						"token":      badtoken,
						"expiration": time.Now().Add(time.Second * time.Duration(cache.GracePeriodSeconds/2)).Unix(),
						"renewable":  true,
					},
				},
			},
		},
		{
			"expired",
			map[string]interface{}{
				host: map[string]interface{}{
					string(cfg.Auth.Method): map[string]interface{}{
						"token":      badtoken,
						"expiration": time.Now().Add(-10 * time.Hour).Unix(),
						"renewable":  false,
					},
				},
			},
		},
		{
			"bad-token-file",
			map[string]interface{}{
				host: map[string]interface{}{
					string(cfg.Auth.Method): "I should be a map",
				},
			},
		},
		{
			"wrong-cached-creds",
			map[string]interface{}{
				host: map[string]interface{}{
					string(cfg.Auth.Method): map[string]interface{}{
						"token":      badtoken,
						"expiration": time.Now().Add(time.Hour * 10).Unix(),
						"renewable":  true,
					},
				},
			},
		},
		{
			"empty-file",
			map[string]interface{}{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTestdata(cacheDir)
			defer clearTestdata(cacheDir)

			writeTokenFile(t, tc.file, cacheUtil.TokenFile())

			helper := NewHelper(nil)

			_, _, err := helper.Get("")
			if err != nil {
				t.Fatal(err)
			}

			token := loadTokenFromFile(t, cacheUtil.TokenFile(), addr, cfg.Auth.Method)

			// Ensure that a new token was obtained
			if token.TokenID() == badtoken {
				t.Fatal("should have obtained a new token but didn't")
			}

			// Ensure that the expiration date is in the future
			if time.Unix(token.Expiration, 0).Before(time.Now()) {
				t.Fatal("cached token should not be expired")
			}
		})
	}
}

func TestMain(m *testing.M) {
	path := os.Getenv("PATH")
	env := awstesting.StashEnv()

	// PATH must be set because awstesting.StashEnv()
	// unsets the value of $PATH and homedir.Expand()
	// requires the $PATH to execute the "sh" command
	os.Setenv("PATH", path)

	defer awstesting.PopEnv(env)
	status := m.Run()
	clearTestdata(testDataDir)
	os.Exit(status)
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

func writeTokenFile(t *testing.T, v interface{}, tokenfile string) {
	data, err := jsonutil.EncodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	writeDataToFile(t, data, tokenfile)
}

func readTokenFile(t *testing.T, tokenfile string) map[string]interface{} {
	data, err := ioutil.ReadFile(tokenfile)
	if err != nil {
		t.Fatal(err)
	}

	var tokenFile map[string]interface{}
	if err = jsonutil.DecodeJSON(data, &tokenFile); err != nil {
		t.Fatal(err)
	}
	
	return tokenFile
}

func writeDataToFile(t *testing.T, data []byte, tokenfile string) {
	if err := os.MkdirAll(filepath.Dir(tokenfile), 0700); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(tokenfile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		t.Fatal(err)
	}
}

func loadTokenFromFile(t *testing.T, filename string, vaultAddr string, method config.VaultAuthMethod) *cache.CachedToken {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var tokenFile = make(map[string]interface{})
	if err = jsonutil.DecodeJSONFromReader(file, &tokenFile); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(vaultAddr)
	if err != nil {
		t.Fatal(err)
	}

	serverTokens, ok := tokenFile[u.Host].(map[string]interface{})
	if !ok {
		t.Fatalf("no cached tokens for host %q", u.Host)
	}

	tokenMap, ok := serverTokens[string(method)].(map[string]interface{})
	if !ok {
		t.Fatalf("no cached token found (host: %q, method: %q)", u.Host, string(method))
	}

	var cachedToken = new(cache.CachedToken)
	if err = mapstructure.Decode(tokenMap, cachedToken); err != nil {
		t.Fatal(err)
	}

	return cachedToken
}

func clearTestdata(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "tokens.json"))
	for _, file := range files {
		os.Remove(file)
	}
}
