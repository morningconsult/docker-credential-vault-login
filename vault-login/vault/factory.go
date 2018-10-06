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

package vault

import "github.com/hashicorp/vault/api"

// ClientFactory is used to create a new vault.Client
// instance. Its methods (WithClient() and NewClient())
// will attempt to obtain a valid Vault token via the
// authentication method specified in the config.json
// file.
type ClientFactory interface {
	// WithClient receives a Vault API client and attempts
	// to give it a token using the method specified in
	// the config.json file. This method is primarily for
	// testing purposes
	WithClient(*api.Client) (Client, *api.Secret, error)

	// NewClient creates a new Vault API client and attempts
	// to give it a valid Vault token by authenticating against
	// against Vault using the method specified in the
	// config.json file
	NewClient() (Client, *api.Secret, error)
}
