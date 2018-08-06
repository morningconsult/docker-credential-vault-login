package config

import (
        "fmt"
        "encoding/json"
        "os"
        "io/ioutil"
)

type VaultAuthMethod string

const (
        VaultAuthMethodAWS = VaultAuthMethod("aws")

        VaultAuthMethodToken = VaultAuthMethod("token")

        DefaultConfigFilePath string = "/etc/docker-credential-vault-login/config.json"

        EnvConfigFilePath string = "DOCKER_CREDS_CONFIG_FILE"
)

type CredHelperConfig struct {
        Method VaultAuthMethod `json:"vault_auth_method"`
        Role   string          `json:"vault_role"`
        Path   string          `json:"vault_secret_path"`
}

func (c *CredHelperConfig) validate() error {
        if c.Path == "" {
                return fmt.Errorf("%s %s", "No path to the location of your secret in Vault",
                        `("vault_secret_path") is provided in configuration file`)
        }

        method := c.Method

        switch method {
        case VaultAuthMethodAWS:
                if c.Role == "" {
                        return fmt.Errorf("%s %s %s", `No Vault role ("vault_role") provided in`,
                                "configuration file (required when the AWS authentication",
                                "method is selected)")
                }
                return nil
        case VaultAuthMethodToken:
                if v := os.Getenv("VAULT_TOKEN"); v == "" {
                        return fmt.Errorf("VAULT_TOKEN environment variable is not set")
                }
                return nil
        default:
                msg := fmt.Sprintf("%s %s %q (must be either %q or %q)", 
                        "Unrecognized Vault authentication method",
                        `("vault_auth_method") value`, method, 
                        VaultAuthMethodAWS, VaultAuthMethodToken))
                return fmt.Errorf(msg)
        }
}

func GetCredHelperConfig() (*CredHelperConfig, error) {
        cfg, err := parseConfig()
        if err != nil {
                return nil, err
        }

        if err = cfg.validate(); err != nil {
                return nil, err
        }
        return cfg, nil
}

func parseConfig() (*CredHelperConfig, error) {
        var path = DefaultConfigFilePath

        if v := os.Getenv(EnvConfigFilePath); v != "" {
                path = v
        }

        data, err := ioutil.ReadFile(path)
        if err != nil {
                return nil, err
        }

        var cfg = new(CredHelperConfig)
        err = json.Unmarshal(data, cfg)
        return cfg, err
}