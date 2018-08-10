// Tests to write:
// * Order of file reading 

package config

import (
        "fmt"
        "os"
        "testing"
)

// TestReadsFileEnv tests that the GetCredHelperConfig function
// looks for and parses the config file specified by the 
// DOCKER_CREDS_CONFIG_FILE environment variable
func TestReadsFileEnv(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile.json"
        cfg := &CredHelperConfig{
                Method:   VaultAuthMethodAWS,
                Role:     "dev-role-iam",
                Secret:   "secret/foo/bar",
                ServerID: "vault.example.com",
        }
        data := marshalJSON(t, cfg)
        makeFile(t, testFilePath, data)
        defer deleteFile(t, testFilePath)

        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)

        if _, err := GetCredHelperConfig(); err != nil {
                t.Errorf("Failed to read config file specified by environment variable %s", 
                        EnvConfigFilePath)
        }
}

// TestConfigFileMissing tests that if the config file located
// at either the default path or the path given by the 
// DOCKER_CREDS_CONFIG_FILE environment variable does not exist,
// GetCredHelperConfig() throws the appropriate error
func TestConfigFileMissing(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile-2.json"
        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)

        if _, err := GetCredHelperConfig(); err != nil {
                if !os.IsNotExist(err) {
                        t.Errorf("%s (expected os.ErrNotExist, got %v)", 
                                "GetCredHelperConfig() returned unexpected error", 
                                err)
                }
        }
}

// TestEmptyConfigFile tests that if the configuration file is
// just an empty JSON, the expected errors are returned.
func TestEmptyConfigFile(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile-3.json"
        var expectedError = fmt.Sprintf("%s\n%s\n%s",
                fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
                "* No Vault authentication method (\"vault_auth_method\") is provided",
                "* No path to the location of your secret in Vault (\"vault_secret_path\") is provided")

        makeFile(t, testFilePath, []byte("{}"))
        defer deleteFile(t, testFilePath)

        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)

        if _, err := GetCredHelperConfig(); err != nil {
                errorsEqual(t, err, expectedError)
        }
}

func TestConfigMissingMethod(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile-4.json"
        var expectedError = fmt.Sprintf("%s\n%s",
                fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
                "* No Vault authentication method (\"vault_auth_method\") is provided")
        
        cfg := &CredHelperConfig{
                Role:     "dev-role-iam",
                Secret:   "secret/foo/bar",
                ServerID: "vault.example.com",
        }
        data := marshalJSON(t, cfg)
        makeFile(t, testFilePath, data)
        defer deleteFile(t, testFilePath)

        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)

        if _, err := GetCredHelperConfig(); err != nil {
                errorsEqual(t, err, expectedError)
        }
}

func TestConfigMissingSecret(t *testing.T) {
        const testFilePath = "/tmp/docker-credential-vault-login-testfile-5.json"
        var expectedError = fmt.Sprintf("%s\n%s",
                fmt.Sprintf("Configuration file %s has the following errors:", testFilePath),
                "* No path to the location of your secret in Vault (\"vault_secret_path\") is provided")
        
        cfg := &CredHelperConfig{
                Method:   VaultAuthMethodAWS
                Role:     "dev-role-iam",
                ServerID: "vault.example.com",
        }
        data := marshalJSON(t, cfg)
        makeFile(t, testFilePath, data)
        defer deleteFile(t, testFilePath)

        os.Setenv(EnvConfigFilePath, testFilePath)
        defer os.Unsetenv(EnvConfigFilePath)

        if _, err := GetCredHelperConfig(); err != nil {
                errorsEqual(t, err, expectedError)
        }
}
