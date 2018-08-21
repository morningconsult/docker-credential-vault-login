package vault

import (
        "fmt"

        "github.com/hashicorp/vault/api"
)

type Credentials struct {
        Username string
        Password string
}

type Client interface {
        GetCredentials(string) (*Credentials, error)
}

// DefaultClient is a wrapper for the Vault API client which
// is guaranteed to possess a token
type defaultClient struct {
        vaultAPI *api.Client
}

func NewDefaultClient(vaultClient *api.Client) Client {
        return &defaultClient{
                vaultAPI: vaultClient,
        }
}

func (d *defaultClient) GetCredentials(path string) (*Credentials, error) {
        var (
                username, password string
                ok                 bool
        )

        secret, err := d.vaultAPI.Logical().Read(path)
        if err != nil {
                return nil, err
        }

        if secret == nil {
                return nil, fmt.Errorf("No secret found at path %q", path)
        }

        creds := secret.Data

        if username, ok = creds["username"].(string); !ok || username == "" {
                return nil, fmt.Errorf("No username found")
        }
        if password, ok = creds["password"].(string); !ok || password == "" {
                return nil, fmt.Errorf("No password found")
        }

        return &Credentials{
                Username: username,
                Password: password,
        }, nil
}