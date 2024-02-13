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
	"fmt"
	"os"
	"path"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agentproxyshared/auth"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/alicloud"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/approle"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/aws"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/azure"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/cert"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/cf"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/gcp"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/jwt"
	"github.com/hashicorp/vault/command/agentproxyshared/auth/kubernetes"
	token_file "github.com/hashicorp/vault/command/agentproxyshared/auth/token-file"
	"github.com/hashicorp/vault/command/agentproxyshared/sink"
	"github.com/hashicorp/vault/command/agentproxyshared/sink/file"
	"golang.org/x/xerrors"
)

// NewClient creates a new Vault client. Note that Vault environment
// variables take precedence over the vaultConfig.
func NewClient( // nolint: gocyclo, gocognit
	methodConfig *config.Method,
	vaultConfig *config.Vault,
) (*api.Client, error) {
	if vaultConfig != nil {
		if os.Getenv(api.EnvVaultAddress) == "" && vaultConfig.Address != "" {
			os.Setenv(api.EnvVaultAddress, vaultConfig.Address) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultAddress)              //nolint:errcheck
		}

		if os.Getenv(api.EnvVaultCACert) == "" && vaultConfig.CACert != "" {
			os.Setenv(api.EnvVaultCACert, vaultConfig.CACert) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultCACert)             //nolint:errcheck
		}

		if os.Getenv(api.EnvVaultCAPath) == "" && vaultConfig.CAPath != "" {
			os.Setenv(api.EnvVaultCAPath, vaultConfig.CAPath) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultCAPath)             //nolint:errcheck
		}

		if os.Getenv(api.EnvVaultSkipVerify) == "" && vaultConfig.TLSSkipVerifyRaw != nil {
			os.Setenv(api.EnvVaultSkipVerify, fmt.Sprintf("%t", vaultConfig.TLSSkipVerify)) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultSkipVerify)                                       //nolint:errcheck
		}

		if os.Getenv(api.EnvVaultClientCert) == "" && vaultConfig.ClientCert != "" {
			os.Setenv(api.EnvVaultClientCert, vaultConfig.ClientCert) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultClientCert)                 //nolint:errcheck
		}

		if os.Getenv(api.EnvVaultClientKey) == "" && vaultConfig.ClientKey != "" {
			os.Setenv(api.EnvVaultClientKey, vaultConfig.ClientKey) //nolint:errcheck
			defer os.Unsetenv(api.EnvVaultClientKey)                //nolint:errcheck
		}
	}

	clientConfig := api.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	return configureToken(client, methodConfig)
}

func configureToken(client *api.Client, methodConfig *config.Method) (*api.Client, error) {
	switch methodConfig.Type {
	case "token":
		if client.Token() == "" {
			tokenRaw, ok := methodConfig.Config["token"]
			if !ok {
				return nil, xerrors.New("missing 'auto_auth.method.config.token' value")
			}

			token, ok := tokenRaw.(string)
			if !ok {
				return nil, xerrors.New("could not convert 'auto_auth.method.config.token' config value to string")
			}

			if token == "" {
				return nil, xerrors.New("'auto_auth.method.config.token' value is empty")
			}

			client.SetToken(token)
		}
	default:
		client.ClearToken()
	}

	return client, nil
}

// BuildSinks creates a set of sinks from the sink configurations.
func BuildSinks(sc []*config.Sink, logger hclog.Logger, client *api.Client) ([]*sink.SinkConfig, error) {
	sinks := make([]*sink.SinkConfig, 0, len(sc))

	for _, ss := range sc {
		switch ss.Type {
		case "file":
			config := &sink.SinkConfig{
				Logger:  logger.Named("sink.file"),
				Config:  ss.Config,
				Client:  client,
				WrapTTL: ss.WrapTTL,
				DHType:  ss.DHType,
				DHPath:  ss.DHPath,
				AAD:     ss.AAD,
			}

			s, err := file.NewFileSink(config)
			if err != nil {
				return nil, xerrors.Errorf("error creating file sink: %w", err)
			}

			config.Sink = s
			sinks = append(sinks, config)
		default:
			return nil, xerrors.Errorf("unknown sink type %q", ss.Type)
		}
	}

	return sinks, nil
}

// BuildAuthMethod creates a new authentication method from config.
func BuildAuthMethod(config *config.Method, logger hclog.Logger) (auth.AuthMethod, error) { // nolint: gocyclo
	// Check if a default namespace has been set
	mountPath := config.MountPath
	if config.Namespace != "" {
		mountPath = path.Join(config.Namespace, mountPath)
	}

	authConfig := &auth.AuthConfig{
		Logger:    logger.Named(fmt.Sprintf("auth.%s", config.Type)),
		MountPath: mountPath,
		Config:    config.Config,
	}

	var (
		method auth.AuthMethod
		err    error
	)

	switch config.Type {
	case "alicloud":
		method, err = alicloud.NewAliCloudAuthMethod(authConfig)
	case "aws":
		method, err = aws.NewAWSAuthMethod(authConfig)
	case "azure":
		method, err = azure.NewAzureAuthMethod(authConfig)
	case "cert":
		method, err = cert.NewCertAuthMethod(authConfig)
	case "cf":
		method, err = cf.NewCFAuthMethod(authConfig)
	case "gcp":
		method, err = gcp.NewGCPAuthMethod(authConfig)
	case "jwt":
		method, err = jwt.NewJWTAuthMethod(authConfig)
	case "kubernetes":
		method, err = kubernetes.NewKubernetesAuthMethod(authConfig)
	case "approle":
		method, err = approle.NewApproleAuthMethod(authConfig)
	case "token-file":
		method, err = token_file.NewTokenFileAuthMethod(authConfig)
	default:
		return nil, xerrors.Errorf("unknown auth method %q", config.Type)
	}

	if err != nil {
		return nil, xerrors.Errorf("error creating %s auth method: %v", config.Type, err)
	}

	return method, nil
}
