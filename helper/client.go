package helper

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

func newVaultClient(config map[string]interface{}) (*api.Client, error) {
	vaultEnvVars := []string{
		api.EnvVaultAddress,
		api.EnvVaultCACert,
		api.EnvVaultClientCert,
		api.EnvVaultClientKey,
		api.EnvVaultClientTimeout,
		api.EnvVaultInsecure,
		api.EnvVaultTLSServerName,
		api.EnvVaultMaxRetries,
		api.EnvVaultToken,
	}

	for _, env := range vaultEnvVars {
		if os.Getenv(strings.ToUpper(env)) != "" {
			continue
		}

		raw, ok := config[env]
		if !ok {
			raw, ok = config[strings.ToLower(env)]
			if !ok {
				continue
			}
		}

		v, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("field 'auto_auth.method.config.%s' could not be converted to a string", env)
		}

		if v != "" {
			os.Setenv(strings.ToUpper(env), v)
			defer os.Unsetenv(env)
		}
	}

	client, err := api.NewClient(nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}