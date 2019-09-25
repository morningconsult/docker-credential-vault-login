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

package vault

import (
	"strings"

	"github.com/hashicorp/vault/api"
	"golang.org/x/xerrors"
)

// Credentials represent Docker credentials
type Credentials struct {
	Username string
	Password string
}

// GetCredentials uses the Vault client to read the secret at
// path
func GetCredentials(path string, client *api.Client) (Credentials, error) {
	var (
		username, password string
		ok                 bool
		missingSecrets     []string
	)

	secret, err := client.Logical().Read(path)
	if err != nil {
		return Credentials{}, xerrors.Errorf("error reading secret: %v", err)
	}

	if secret == nil {
		return Credentials{}, xerrors.Errorf("No secret found in Vault at path %q", path)
	}

	creds := secret.Data

	if username, ok = creds["username"].(string); !ok || username == "" {
		missingSecrets = append(missingSecrets, "username")
	}
	if password, ok = creds["password"].(string); !ok || password == "" {
		missingSecrets = append(missingSecrets, "password")
	}

	if len(missingSecrets) > 0 {
		return Credentials{}, xerrors.Errorf("No %s found in Vault at path %q", strings.Join(missingSecrets, " or "), path)
	}

	return Credentials{
		Username: username,
		Password: password,
	}, nil
}
