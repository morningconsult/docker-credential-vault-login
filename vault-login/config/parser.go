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

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/mitchellh/go-homedir"
)

type VaultAuthMethod string

const (
	VaultAuthMethodAWSIAM = VaultAuthMethod("iam")

	VaultAuthMethodAWSEC2 = VaultAuthMethod("ec2")

	VaultAuthMethodToken = VaultAuthMethod("token")

	DefaultConfigFilePath string = "/etc/docker-credential-vault-login/config.json"

	EnvConfigFilePath string = "DOCKER_CREDS_CONFIG_FILE"
)

type AuthConfig struct {

	// Method is the method Vault will use to authenticate a user. Accepted
	// values include "token", "iam", and "ec2". This field is
	// always required.
	Method VaultAuthMethod `json:"method"`

	// Role is the Vault role which has been configured to be able to
	// authenticate via the EC2 or IAM method (this field is only required
	// when either "iam" or "ec2" is chosen as the authentication method).
	Role string `json:"role"`

	// ServerID is used as the value of the X-Vault-AWS-IAM-Server-ID when
	// Vault makes an sts:GetCallerIdentity request to AWS as part of the
	// AWS IAM authentication method. This field is optional and is only
	// used when "iam" is chosen as the authentication method.
	ServerID string `json:"iam_server_id_header"`

	// AWSMountPath is used to specify the path at which the AWS secrets
	// engine is enable (if at all). If this is empty, the default mount
	// path "aws" will be used instead.
	AWSMountPath string `json:"aws_mount_path"`
}

type CacheConfig struct {

	// Dir is the directory where cached files (including logs and tokens)
	// will be written to disk.
	Dir string `json:"dir"`

	// DisableTokenCaching, if true, will disable the caching of Vault
	// client tokens.
	DisableTokenCaching bool `json:"disable_token_caching"`
}

type CredHelperConfig struct {

	// Auth is used to specify the authentication parameters
	Auth AuthConfig `json:"auth"`

	// ClientConfig is used to configure the Vault API client used to
	// make requests to your Vault server.
	Client map[string]string `json:"client"`

	// CacheConfig is the used to configure where cached files (including
	// logs and tokens) should be stored.
	Cache CacheConfig

	// Secret is the path in Vault at which the Docker credentials are
	// stored (e.g. "secret/foo/bar"). This field is always required.
	Secret string `json:"secret_path"`

	// Path is the full path to the config.json file. This field is
	// primarily used for error logging.
	Path string `json:"-"`
}

// ParseConfigFile first searches for the config.json file at the
// DOCKER_CREDS_CONFIG_FILE environment variable if it is set, otherwise it
// searches for it at the DefaultConfigFilePath location. If it is found in
// neither location, ParseConfigFile will return an error. If it finds the
// config.json file, ParseConfigFile will parse and validate it.
func ParseConfigFile() (*CredHelperConfig, error) {
	cfg, err := parseConfigFile()
	if err != nil {
		return nil, err
	}

	if err = cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseConfigFile() (*CredHelperConfig, error) {
	var rawPath = DefaultConfigFilePath

	if v := os.Getenv(EnvConfigFilePath); v != "" {
		rawPath = v
	}

	path, err := homedir.Expand(rawPath)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg = new(CredHelperConfig)
	if err = jsonutil.DecodeJSONFromReader(file, cfg); err != nil {
		return nil, err
	}

	cfg.Path = path
	return cfg, nil
}

func (c *CredHelperConfig) validate() error {
	var errors []string

	switch c.Auth.Method {
	case "":
		errors = append(errors, `No Vault authentication method (auth.method) is provided`)
	case VaultAuthMethodToken:
	case VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2:
		if c.Auth.Role == "" {
			errors = append(errors, fmt.Sprintf("%s %s", `No Vault role ("role") is`,
				"provided (required when the AWS authentication method is chosen)"))
		}
		if c.Auth.AWSMountPath == "" {
			c.Auth.AWSMountPath = "aws"
		}
	default:
		errors = append(errors, fmt.Sprintf("%s %s %q (must be one of %q, %q, or %q)",
			"Unrecognized Vault authentication method", `(auth.method) value`,
			c.Auth.Method, VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2, VaultAuthMethodToken))
	}

	if c.Secret == "" {
		errors = append(errors, fmt.Sprintf("%s %s", "No path to the location of",
			`your secret in Vault ("secret_path") is provided`))
	}

	if len(errors) > 0 {
		return fmt.Errorf("Configuration file %s has the following errors:\n* %s",
			c.Path, strings.Join(errors, "\n* "))
	}

	return nil
}
