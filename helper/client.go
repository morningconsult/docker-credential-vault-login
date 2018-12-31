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
