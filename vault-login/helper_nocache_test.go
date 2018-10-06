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

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/api"

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
