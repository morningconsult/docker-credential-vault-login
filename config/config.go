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

package config

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	vaultconfig "github.com/hashicorp/vault/command/agent/config"
)

const noSinkHCLTemplate string = `
%s

cache {
        use_auto_auth_token = true
}

listener "tcp" {
	address     = "127.0.0.1:8100"
	tls_disable = true
}
`

// NOTE: This must match the error in Vault EXACTLY:
// https://github.com/hashicorp/vault/blob/13c56f5f92a91bcc9a2ab02daed0910b1828c94f/command/agent/config/config.go#L143
//
// This error message must always be kept up to date.
const errNoSinkMsg = "auto_auth requires at least one sink or cache.use_auto_auth_token=true "

// SecretsTable is used to lookup the path to where your Docker
// credentials are stored in Vault based on a given hostname.
type SecretsTable struct {
	oneSecret        string
	registryToSecret map[string]string
}

// GetPath returns the path to the Vault secret where your Docker
// credentials are kept for the registry.
func (s SecretsTable) GetPath(registry string) string {
	if s.oneSecret != "" {
		return s.oneSecret
	}
	return s.registryToSecret[registry]
}

// LoadConfig will parse the configuration file and return a
// configuration struct.
func LoadConfig(configFile string) (*vaultconfig.Config, error) {
	// Try to parse config file once
	config, err := vaultconfig.LoadConfig(configFile, nil)
	if err != nil {
		// No sinks in configuration file - do a workaround to allow no sinks
		if err.Error() != errNoSinkMsg {
			return nil, err
		}
		data, err := ioutil.ReadFile(configFile) // nolint: gosec
		if err != nil {
			return nil, err
		}

		// Add `cache` and `listener` stanzas so that vaultconfig.LoadConfig
		// will not return a validation error. With the Vault agent, if Auto Auth
		// is used without caching, then there MUST be at least one sink. If
		// caching is used in conjunction with Auto Auth, then sinks are optional.
		// Therefore, this function will create a copy of the configuration file,
		// add a `cache` stanza and a `listener` stanza, write it to a temporary
		// file, and pass this temporary file to vaultconfig.LoadConfig. This
		// will bypass the sink requirement and thus allow no sinks to be used.
		hcl := fmt.Sprintf(noSinkHCLTemplate, string(data))

		// Write modified configuration file string to temporary file
		configFileBase := filepath.Base(configFile)
		tempFile, err := ioutil.TempFile("", configFileBase+".*")
		if err != nil {
			return nil, err
		}
		defer os.Remove(tempFile.Name())

		if _, err = tempFile.Write([]byte(hcl)); err != nil {
			return nil, err
		}
		if err = tempFile.Close(); err != nil {
			return nil, err
		}

		// Reload configuration with temporary file
		config, err = vaultconfig.LoadConfig(tempFile.Name(), nil)
		if err != nil {
			return nil, err
		}
	}
	if config == nil {
		return nil, errors.New("no configuration found")
	}
	if config.AutoAuth == nil {
		return nil, errors.New("no 'auto_auth' block found in configuration file")
	}
	return config, nil
}

// BuildSecretsTable parses the auto_auth.method.secrets.config stanza
// of the configuration file. The value of this field may be either a
// string or a map[string]string.
func BuildSecretsTable(config map[string]interface{}) (SecretsTable, error) { // nolint: gocyclo
	secretRaw, ok := config["secret"]
	if !ok {
		return SecretsTable{}, errors.New("path to the secret where your Docker credentials are stored " +
			"must be specified via in the field 'auto_auth.method.config.secret' of the config file")
	}
	switch s := secretRaw.(type) {
	case string:
		if s == "" {
			return SecretsTable{}, errors.New("field 'auto_auth.method.config.secret' is empty")
		}
		return SecretsTable{oneSecret: s}, nil
	case []map[string]interface{}:
		if len(s) == 0 {
			return SecretsTable{}, errors.New("field 'auto_auth.method.config.secret' is empty")
		}
		obj := make(map[string]string)
		for host, pathRaw := range s[0] {
			if path, ok := pathRaw.(string); ok && path != "" && host != "" {
				obj[host] = path
			}
		}
		if len(obj) == 0 {
			return SecretsTable{}, errors.New("'auto_auth.method.config.secret' should be a map[string]string")
		}
		return SecretsTable{registryToSecret: obj}, nil
	default:
		return SecretsTable{}, errors.New("field 'auto_auth.method.config.secret' must be either a string or a map")
	}
}
