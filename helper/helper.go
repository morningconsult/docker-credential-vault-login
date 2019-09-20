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
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/morningconsult/docker-credential-vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault"
)

const (
	EnvConfigFile     = "DCVL_CONFIG_FILE"
	EnvDisableCaching = "DCVL_DISABLE_CACHE"
	EnvSecretPath     = "DCVL_SECRET"
	defaultConfigFile = "/etc/docker-credential-vault-login/config.hcl"
)

var (
	notImplementedError = fmt.Errorf("not implemented")
	defaultAuthTimeout  = 10 * time.Second
)

type Options struct {
	Logger      hclog.Logger
	Client      *api.Client
	Secret      string
	EnableCache bool
	AuthTimeout int64
	WrapTTL     time.Duration
	AuthMethod  auth.AuthMethod
	Sinks       []*sink.SinkConfig
}

type Helper struct {
	logger       hclog.Logger
	client       *api.Client
	secret       string
	cacheEnabled bool
	authTimeout  time.Duration
	wrapTTL      time.Duration
	authMethod   auth.AuthMethod
	sinks        []*sink.SinkConfig
}

func New(opts Options) *Helper {
	timeout := defaultAuthTimeout
	if opts.AuthTimeout != 0 {
		timeout = time.Duration(opts.AuthTimeout) * time.Second
	}

	return &Helper{
		logger:       opts.Logger,
		client:       opts.Client,
		secret:       opts.Secret,
		cacheEnabled: opts.EnableCache,
		authTimeout:  timeout,
		wrapTTL:      opts.WrapTTL,
		authMethod:   opts.AuthMethod,
		sinks:        opts.Sinks,
	}
}

func (h *Helper) Add(creds *credentials.Credentials) error {
	return notImplementedError
}

func (h *Helper) Delete(serverURL string) error {
	return notImplementedError
}

func (h *Helper) List() (map[string]string, error) {
	return nil, notImplementedError
}

func (h *Helper) Get(serverURL string) (string, string, error) {
	if h.client.Token() == "" { // TODO: Use better way of ensuring this happens only when "token" method is used
		if h.cacheEnabled {
			cloned, err := h.client.Clone()
			if err != nil {
				h.logger.Error("error cloning Vault API client", "error", err)
				return "", "", credentials.NewErrCredentialsNotFound()
			}

			// Get any cached tokens
			cachedTokens := cache.GetCachedTokens(h.logger.Named("cache"), config.AutoAuth.Sinks, cloned)
			if len(cachedTokens) < 1 {
				h.logger.Info("No cached token(s) were read. Re-authenticating.")
			}

			// Renew the cached tokens
			for _, token := range cachedTokens {
				if _, err := h.client.Auth().Token().RenewTokenAsSelf(token, 0); err != nil {
					h.logger.Error("error renewing token", "error", err)
				}
			}

			// Use any token to get credentials
			for _, token := range cachedTokens {
				h.client.SetToken(token)

				// Get credentials
				creds, err := vault.GetCredentials(h.secret, h.client)
				if err != nil {
					h.logger.Error("error reading secret from Vault", "error", err)
					continue
				}
				return creds.Username, creds.Password, nil
			}
		}

		// Failed to read secret with cached token. Reauthenticate.
		h.client.ClearToken()

		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        h.logger.Named("sink.server"),
			Client:        h.client,
			ExitAfterAuth: true,
		})

		ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
			Logger:  h.logger.Named("auth.handler"),
			Client:  h.client,
			WrapTTL: h.wrapTTL,
		})

		ctx, cancel := context.WithTimeout(context.Background(), h.authTimeout)
		defer cancel()

		newTokenCh := make(chan string)

		go ah.Run(ctx, h.authMethod)
		go ss.Run(ctx, newTokenCh, h.sinks)

		var token string
		select {
		case <-ctx.Done():
			h.logger.Error(fmt.Sprintf("failed to get credentials within timeout (%s)", h.authTimeout.String()))
			<-ah.DoneCh
			<-ss.DoneCh
			return "", "", credentials.NewErrCredentialsNotFound()
		case token = <-ah.OutputCh:
			// will have to unwrap token if wrapped
			h.logger.Info("successfully authenticated")
		}

		if h.cacheEnabled {
			newTokenCh <- token
			select {
			case <-ctx.Done():
				h.logger.Error(fmt.Sprintf("failed to write token to sink(s) within the timeout (%s)", h.authTimeout.String()))
				<-ah.DoneCh
				<-ss.DoneCh
				return "", "", credentials.NewErrCredentialsNotFound()
			case <-ss.DoneCh:
			}
		}

		cancel()
		<-ah.DoneCh
		<-ss.DoneCh

		h.client.SetToken(token)
	}

	// Get credentials
	creds, err := vault.GetCredentials(h.secret, h.client)
	if err != nil {
		h.logger.Error("error reading secret from Vault", "error", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	return creds.Username, creds.Password, nil
}

func (h *Helper) parseConfig(configFile string) (*config.Config, error) {
	config, err := config.LoadConfig(configFile, h.logger)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errors.New("no configuration read. Please provide the configuration file with the " +
			EnvConfigFile + " environment variable.")
	}

	if config.AutoAuth == nil {
		return nil, errors.New("no 'auto_auth' block found")
	}

	return config, nil
}
