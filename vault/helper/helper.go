package helper

import (
        "fmt"
        
        vault "github.com/hashicorp/vault/api"
        "github.com/docker/docker-credential-helpers/credentials"
)

var notImplementedError = fmt.Errorf("not implemented")

type Helper struct {
        // VaultSecretPath is the path in Vault in which
        vaultSecretPath string

        // VaultClient is the client used to interface with 
        // a Vault server via HTTP
        vaultClient *vault.Client
}

func NewHelper(path string, client *vault.Client) Helper {
        return Helper{
                vaultSecretPath: path,
                vaultClient:     client,
        }
}

func (h Helper) Add(creds *credentials.Credentials) error {
        return notImplementedError
}

func (h Helper) Delete(serverURL string) error {
        return notImplementedError
}

func (h Helper) Get(serverURL string) (string, string, error) {
        var (
                username, password string
                ok                 bool
        )

        secret, err := h.vaultClient.Logical().Read(h.vaultSecretPath)
        if err != nil {
                return "", "", fmt.Errorf("Error fetching secret from Vault: %+v", err)
        }

        if secret == nil {
                return "", "", fmt.Errorf("No secret found at path %q", h.vaultSecretPath)
        }

        creds := secret.Data

        if username, ok = creds["username"].(string); !ok || username == "" {
                return "", "", fmt.Errorf("No username found")
        }
        if password, ok = creds["password"].(string); !ok || password == "" {
                return "", "", fmt.Errorf("No password found")
        }

        return username, password, nil
}

func (h Helper) List() (map[string]string, error) {
        // might be good to store secrets like
        // "dockerServerURL" : {
        //        "username": "foo"
        //        "password": "bar"
        // }"
        return nil, notImplementedError
}
