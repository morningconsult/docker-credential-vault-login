// Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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

package helper

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
)

func newVaultClient(method *config.Method) (*api.Client, error) {
	vaultEnvVars := []string{
		api.EnvVaultAddress,
		api.EnvVaultCACert,
		api.EnvVaultClientCert,
		api.EnvVaultClientKey,
		api.EnvVaultClientTimeout,
		api.EnvVaultInsecure,
		api.EnvVaultTLSServerName,
		api.EnvVaultMaxRetries,
	}

	for _, env := range vaultEnvVars {
		if os.Getenv(strings.ToUpper(env)) != "" {
			continue
		}

		raw, ok := method.Config[env]
		if !ok {
			raw, ok = method.Config[strings.ToLower(env)]
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

	switch method.Type {
	case "token":
		token := os.Getenv(api.EnvVaultToken)
		if token == "" {
			tokenRaw, ok := method.Config["token"]
			if !ok {
				return nil, errors.New("missing 'auto_auth.method.config.token' value")
			}
			token, ok = tokenRaw.(string)
			if !ok {
				return nil, errors.New("could not convert 'auto_auth.method.config.token' config value to string")
			}
		}
		if token == "" {
			return nil, fmt.Errorf("No token provided. If the \"token\" auto_auth method is to be used, "+
				"either the %s environment variable must be set or the 'auto_auth.method.config.token' "+
				"field of the configuration file must be set.", api.EnvVaultToken)
		}
		client.SetToken(token)
	default:
	}

	return client, nil
}
