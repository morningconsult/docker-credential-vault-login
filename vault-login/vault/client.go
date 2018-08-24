package vault

import (
        "fmt"
        "strings"

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
                missingSecrets     []string
        )

        secret, err := d.vaultAPI.Logical().Read(path)
        if err != nil {
                return nil, err
        }

        if secret == nil {
                return nil, fmt.Errorf("No secret found in Vault at path %q", path)
        }

        creds := secret.Data

        if username, ok = creds["username"].(string); !ok || username == "" {
                missingSecrets = append(missingSecrets, "username")
        }
        if password, ok = creds["password"].(string); !ok || password == "" {
                missingSecrets = append(missingSecrets, "password")
        }

        if len(missingSecrets) > 0 {
                return nil, fmt.Errorf("No %s found in Vault at path %q", strings.Join(missingSecrets, " or "), path)
        }

        return &Credentials{
                Username: username,
                Password: password,
        }, nil
}