package config

import (
        "fmt"
        "os"
        "strings"

        "github.com/mitchellh/go-homedir"
        "github.com/hashicorp/vault/helper/jsonutil"
)

type VaultAuthMethod string

const (
	VaultAuthMethodAWSIAM = VaultAuthMethod("iam")
	
	VaultAuthMethodAWSEC2 = VaultAuthMethod("ec2")

        VaultAuthMethodToken = VaultAuthMethod("token")

        DefaultConfigFilePath string = "/etc/docker-credential-vault-login/config.json"

        EnvConfigFilePath string = "DOCKER_CREDS_CONFIG_FILE"
)

type CredHelperConfig struct {
        Method   VaultAuthMethod `json:"vault_auth_method"`
        Role     string          `json:"vault_role"`
        Secret   string          `json:"vault_secret_path"`
        ServerID string          `json:"vault_iam_server_id_header_value"`
        Path     string          `json:"-"`
}

func GetCredHelperConfig() (*CredHelperConfig, error) {
        cfg, err := parseConfigFile()
        if err != nil {
                return nil, err
        }

        if err = cfg.validate(); err != nil {
                return nil, err
        }
        return cfg, nil
}

func parseConfigFile() (*CredHelperConfig, error) {
        var rawPath = DefaultConfigFilePath

        if v := os.Getenv(EnvConfigFilePath); v != "" {
                rawPath = v
        }

        path, err := homedir.Expand(rawPath)
        if err != nil {
                return nil, err
        }

        file, err := os.Open(path)
        if err != nil {
                return nil, err
	}
	
	defer file.Close()

        var cfg = new(CredHelperConfig)
        if err = jsonutil.DecodeJSONFromReader(file, cfg); err != nil {
                return cfg, err
        }

        cfg.Path = path
        return cfg, nil
}

func (c *CredHelperConfig) validate() error {
        var errors []string

        method := c.Method

        switch method {
        case "":
                errors = append(errors, `No Vault authentication method ("vault_auth_method") is provided`)
        case VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2:
                if c.Role == "" {
                        errors = append(errors, fmt.Sprintf("%s %s", `No Vault role ("vault_role") is`,
                                "provided (required when the AWS authentication method is chosen)"))
		}
        case VaultAuthMethodToken:
                if v := os.Getenv("VAULT_TOKEN"); v == "" {
                        errors = append(errors, fmt.Sprintf("VAULT_TOKEN environment variable is not set"))
                }
        default:
                errors = append(errors, fmt.Sprintf("%s %s %q (must be one of %q, %q, or %q)",
			"Unrecognized Vault authentication method", `("vault_auth_method") value`,
			method, VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2, VaultAuthMethodToken))
        }

        if c.Secret == "" {
                errors = append(errors, fmt.Sprintf("%s %s", "No path to the location of",
                        `your secret in Vault ("vault_secret_path") is provided`))
        }

        if len(errors) > 0 {
                return fmt.Errorf("Configuration file %s has the following errors:\n* %s", 
                        c.Path, strings.Join(errors, "\n* "))
        }
        return nil
}
