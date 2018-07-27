package config

import (
        "fmt"
        "ioutil"
        "os"
)

const (
        // DefaultConfigPath is the default location where this applicatoin
        // expects to find the config.json file.
        DefaultConfigPath string = "/etc/docker-vault-login/config.json"

        // EnvConfigPath is the path to the config.json file
        EnvConfigPath string = "DOCKER_VAULT_CRED_HELPER_CONFIG"
)

type VaultConfig struct {
        // Address is the address of the Vault server. This should be a complete
        // URL such as "http://vault.example.com".
        Address string `json:`

        // Path is the path at which your Docker login credentials are stored.
        Path string

        // Token is the Vault token used to authenticate HTTP requests to Vault
        Token string
}

func ParseConfig() (*VaultConfig, error) {
        data, err := parseConfigFile()
        if err != nil {
                return nil, fmt.Errorf("error reading config file: %+v", err)
        }


}

func parseConfigFile() ([]byte, error) {
        var path string

        if d := os.Getenv(EnvConfigPath) != "" {
                path = d
        } else {
                path = DefaultConfigPath
        }

        return ioutil.ReadFile(path)
}
