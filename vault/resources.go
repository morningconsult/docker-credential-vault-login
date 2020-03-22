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
	"path"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/alicloud"
	"github.com/hashicorp/vault/command/agent/auth/approle"
	"github.com/hashicorp/vault/command/agent/auth/aws"
	"github.com/hashicorp/vault/command/agent/auth/azure"
	"github.com/hashicorp/vault/command/agent/auth/cert"
	"github.com/hashicorp/vault/command/agent/auth/cf"
	"github.com/hashicorp/vault/command/agent/auth/gcp"
	"github.com/hashicorp/vault/command/agent/auth/jwt"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"golang.org/x/xerrors"
)

// buildAuthMethod creates a new authentication method from config.
func buildAuthMethod(config *config.Method, logger hclog.Logger) (auth.AuthMethod, error) { // nolint: gocyclo
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
	default:
		return nil, xerrors.Errorf("unknown auth method %q", config.Type)
	}

	if err != nil {
		return nil, xerrors.Errorf("error creating %s auth method: %v", config.Type, err)
	}

	return method, nil
}

// buildSinks creates a set of sinks from the sink configurations.
func buildSinks(sc []*config.Sink, logger hclog.Logger, client *api.Client) ([]*sink.SinkConfig, error) {
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
