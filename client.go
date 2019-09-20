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

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
)

func newVaultClient(vaultConfig *config.Vault) (*api.Client, error) {
	if vaultConfig != nil {
		if os.Getenv(api.EnvVaultAddress) == "" && vaultConfig.Address != "" {
			os.Setenv(api.EnvVaultAddress, vaultConfig.Address)
			defer os.Unsetenv(api.EnvVaultAddress)
		}
		if os.Getenv(api.EnvVaultCACert) == "" && vaultConfig.CACert != "" {
			os.Setenv(api.EnvVaultCACert, vaultConfig.CACert)
			defer os.Unsetenv(api.EnvVaultCACert)
		}
		if os.Getenv(api.EnvVaultCAPath) == "" && vaultConfig.CAPath != "" {
			os.Setenv(api.EnvVaultCAPath, vaultConfig.CAPath)
			defer os.Unsetenv(api.EnvVaultCAPath)
		}
		if os.Getenv(api.EnvVaultSkipVerify) == "" && vaultConfig.TLSSkipVerifyRaw != nil {
			os.Setenv(api.EnvVaultSkipVerify, fmt.Sprintf("%t", vaultConfig.TLSSkipVerify))
			defer os.Unsetenv(api.EnvVaultSkipVerify)
		}
		if os.Getenv(api.EnvVaultClientCert) == "" && vaultConfig.ClientCert != "" {
			os.Setenv(api.EnvVaultClientCert, vaultConfig.ClientCert)
			defer os.Unsetenv(api.EnvVaultClientCert)
		}
		if os.Getenv(api.EnvVaultClientKey) == "" && vaultConfig.ClientKey != "" {
			os.Setenv(api.EnvVaultClientKey, vaultConfig.ClientCert)
			defer os.Unsetenv(api.EnvVaultClientKey)
		}
	}
	clientConfig := api.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}
	return api.NewClient(clientConfig)
}
