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

func GetCredentials(path string, client *api.Client) (*Credentials, error) {
	var (
		username, password string
		ok                 bool
		missingSecrets     []string
	)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("error reading secret: %v", err)
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
