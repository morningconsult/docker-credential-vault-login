// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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

package test

import (
	"fmt"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
	"net/http"
	"testing"
)

func StartTestCluster(t *testing.T) *vault.TestCluster {
	base := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(log.Error),
	}

	cluster := vault.NewTestCluster(t, base, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	return cluster
}

// NewPreConfiguredVaultClient creates a new Vault API client and configures it to use
// the same settings as the vault.TestCluster
func NewPreConfiguredVaultClient(t *testing.T, cluster *vault.TestCluster) *api.Client {
	cores := cluster.Cores

	core := cores[0].Core
	vault.TestWaitActive(t, core)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("https://127.0.0.1:%d", cores[0].Listeners[0].Address.Port)
	config.HttpClient.Transport.(*http.Transport).TLSClientConfig = cores[0].TLSConfig

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	client.SetToken(cluster.RootToken)
	return client
}

func WriteSecret(t *testing.T, client *api.Client, secretPath string, secret map[string]interface{}) {
	if _, err := client.Logical().Write(secretPath, secret); err != nil {
		t.Fatal(err)
	}
}

func DeleteSecret(t *testing.T, client *api.Client, secretPath string) {
	if _, err := client.Logical().Delete(secretPath); err != nil {
		t.Fatal(err)
	}
}
