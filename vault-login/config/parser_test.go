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

package config

import (
	"fmt"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
	"os"
	"testing"
)

const testFilePath = "testdata/testconfig.json"

// TestReadsFileEnv tests that the ParseConfigFile function
// looks for and parses the config file specified by the
// DOCKER_CREDS_CONFIG_FILE environment variable
func TestReadsFileEnv(t *testing.T) {
	cfg := &CredHelperConfig{
		Auth: AuthConfig{
			Method:   VaultAuthMethodAWSIAM,
			Role:     "dev-role-iam",
			ServerID: "vault.example.com",
		},
		Secret:   "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		t.Errorf("Failed to read config file specified by environment variable %s",
			EnvConfigFilePath)
	}
}

// TestConfigFileMissing tests that if the config file located
// at either the default path or the path given by the
// DOCKER_CREDS_CONFIG_FILE environment variable does not exist,
// ParseConfigFile() throws the appropriate error
func TestConfigFileMissing(t *testing.T) {
	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		if !os.IsNotExist(err) {
			t.Errorf("%s (expected os.ErrNotExist, got %v)",
				"ParseConfigFile() returned unexpected error",
				err)
		}
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

// TestEmptyConfigFile tests that if the configuration file is
// just an empty JSON, the expected errors are returned.
func TestEmptyConfigFile(t *testing.T) {
	var expectedError = fmt.Sprintf("%s\n%s\n%s",
		fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
		"* No Vault authentication method (auth.method) is provided",
		"* No path to the location of your secret in Vault (\"secret_path\") is provided")

	test.MakeFile(t, testFilePath, []byte("{}"))
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		test.ErrorsEqual(t, err, expectedError)
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

// TestConfigMissingMethod tests that ParseConfigFile
// return the expected error message when no authentication
// method is provided in the configuration file.
func TestConfigMissingMethod(t *testing.T) {
	var expectedError = fmt.Sprintf("%s\n%s",
		fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
		"* No Vault authentication method (auth.method) is provided")

	cfg := &CredHelperConfig{
		Auth: AuthConfig{
			Role:     "dev-role-iam",
			ServerID: "vault.example.com",
		},
		Secret:   "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		test.ErrorsEqual(t, err, expectedError)
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

// TestConfigMissingSecret tests that ParseConfigFile
// returns the expected error message when no path to a Vault
// secret is provided in the configuration file. This secret
// is the location in Vault at which your Docker credentials
// are stored
func TestConfigMissingSecret(t *testing.T) {
	var expectedError = fmt.Sprintf("%s\n%s",
		fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
		"* No path to the location of your secret in Vault (\"secret_path\") is provided")

	cfg := &CredHelperConfig{
		Auth: AuthConfig{
			Method:   VaultAuthMethodAWSIAM,
			Role:     "dev-role-iam",
			ServerID: "vault.example.com",
		},
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		test.ErrorsEqual(t, err, expectedError)
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

// TestConfigMissingRole tests that ParseConfigFile
// returns the expected error message when no Vault role
// is provided in the configuration file when the AWS auth
// method is chosen
func TestConfigMissingRole(t *testing.T) {
	var expectedError = fmt.Sprintf("%s\n%s%s",
		fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
		"* No Vault role (\"role\") is provided (required when ",
		"the AWS authentication method is chosen)")

	cfg := &CredHelperConfig{
		Auth: AuthConfig{
			Method:   VaultAuthMethodAWSIAM,
			ServerID: "vault.example.com",
		},
		Secret:   "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		test.ErrorsEqual(t, err, expectedError)
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

// TestConfigBadAuthMethod tests that if an unsupported
// authentication method is provided in the "auth_method"
// field of the config.json file, ParseConfigFile returns
// the appropriate error.
func TestConfigBadAuthMethod(t *testing.T) {
	const badMethod = "potato"

	var expectedError = fmt.Sprintf("%s\n* %s",
		fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
		fmt.Sprintf(`Unrecognized Vault authentication method (auth.method) value %q (must be one of "iam", "ec2", or "token")`, badMethod),
	)

	cfg := &CredHelperConfig{
		Auth: AuthConfig{
			Method:   VaultAuthMethod(badMethod),
		},
		Secret:   "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	if _, err := ParseConfigFile(); err != nil {
		test.ErrorsEqual(t, err, expectedError)
	} else {
		t.Fatal("Expected to receive an error but didn't")
	}
}

func TestConfigGoodClientConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"auth": map[string]interface{}{
			"method": "token",
		},
		"client": map[string]interface{}{
			"vault_token": "unique Vault client token",
		},
		"secret_path": "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	_, err := ParseConfigFile()
	if err != nil {
		t.Fatal("should not have received an error")
	}
}

func TestConfigBadClientConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"auth": map[string]interface{}{
			"method": "token",
		},
		"client": map[string]interface{}{
			// "client" should be a map[string]string
			"vault_token": map[string]interface{}{
				"key": "value",
			},
		},
		"secret_path": "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	_, err := ParseConfigFile()
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestConfigGoodCacheConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"auth": map[string]interface{}{
			"method": "token",
		},
		"cache": map[string]interface{}{
			"disable_token_caching": true,
		},
		"secret_path": "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	c, err := ParseConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if !c.Cache.DisableTokenCaching {
		t.Fatal("cache.disable_token_caching should have been true")
	}
}

func TestConfigBadCacheConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"auth": map[string]interface{}{
			"method": "token",
		},
		"cache": map[string]interface{}{
			"disable_token_caching": "not a bool!",
		},
		"secret_path": "secret/foo/bar",
	}
	data := test.EncodeJSON(t, cfg)
	test.MakeFile(t, testFilePath, data)
	defer test.DeleteFile(t, testFilePath)

	path := os.Getenv(EnvConfigFilePath)
	os.Setenv(EnvConfigFilePath, testFilePath)
	defer os.Setenv(EnvConfigFilePath, path)

	_, err := ParseConfigFile()
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}
