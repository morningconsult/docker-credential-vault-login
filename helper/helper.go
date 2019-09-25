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
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"golang.org/x/xerrors"

	"github.com/morningconsult/docker-credential-vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault"
)

var (
	errNotImplemented  = errors.New("not implemented")
	defaultAuthTimeout = 10 * time.Second
)

// Options is used to configure a new Helper instance
type Options struct {
	Logger      hclog.Logger
	Client      *api.Client
	Secret      string
	EnableCache bool
	AuthTimeout int64
	WrapTTL     time.Duration
	AuthConfig  *config.AutoAuth
}

// Helper implements a Docker credential helper which will
// fetch Docker credentials from Vault and pass them to
// the Docker daemon in order to authenticate to a private
// Docker registry
type Helper struct {
	logger       hclog.Logger
	client       *api.Client
	secret       string
	cacheEnabled bool
	authTimeout  time.Duration
	authConfig   *config.AutoAuth
}

// New creates a new Helper instance
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
		authConfig:   opts.AuthConfig,
	}
}

// Add is not implemented
func (h *Helper) Add(creds *credentials.Credentials) error {
	return errNotImplemented
}

// Delete is not implemented
func (h *Helper) Delete(serverURL string) error {
	return errNotImplemented
}

// List is not implemented
func (h *Helper) List() (map[string]string, error) {
	return nil, errNotImplemented
}

// Get will lookup Docker credentials in Vault and pass them
// to the Docker daemon.
func (h *Helper) Get(_ string) (string, string, error) { // nolint: gocyclo
	if h.client.Token() != "" {
		// Get credentials with provided token
		creds, err := vault.GetCredentials(h.secret, h.client)
		if err != nil {
			h.logger.Error("error reading secret from Vault", "error", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}
		return creds.Username, creds.Password, nil
	}

	if h.cacheEnabled {
		clone, err := h.client.Clone()
		if err != nil {
			h.logger.Error("error cloning Vault API client", "error", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		// Get any cached tokens
		cachedTokens := cache.GetCachedTokens(h.logger.Named("cache"), h.authConfig.Sinks, clone)
		if len(cachedTokens) < 1 {
			h.logger.Info("no cached token(s) were read. Re-authenticating.")
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
	token, err := h.authenticate()
	if err != nil {
		h.logger.Error("error authenticating", "error", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	h.client.SetToken(token)

	// Get credentials
	creds, err := vault.GetCredentials(h.secret, h.client)
	if err != nil {
		h.logger.Error("error reading secret from Vault", "error", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	return creds.Username, creds.Password, nil
}

func (h *Helper) authenticate() (string, error) {
	sinks, err := vault.BuildSinks(h.authConfig.Sinks, h.logger, h.client)
	if err != nil {
		return "", xerrors.Errorf("error building sinks: %w", err)
	}

	method, err := vault.BuildAuthMethod(h.authConfig.Method, h.logger)
	if err != nil {
		return "", xerrors.Errorf("error creating auth method: %w", err)
	}

	ss := sink.NewSinkServer(&sink.SinkServerConfig{
		Logger:        h.logger.Named("sink.server"),
		Client:        h.client,
		ExitAfterAuth: true,
	})

	ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
		Logger:  h.logger.Named("auth.handler"),
		Client:  h.client,
		WrapTTL: h.authConfig.Method.WrapTTL,
	})

	ctx, cancel := context.WithTimeout(context.Background(), h.authTimeout)
	defer cancel()

	newTokenCh := make(chan string)

	go ah.Run(ctx, method)
	go ss.Run(ctx, newTokenCh, sinks)

	var token string
	select {
	case <-ctx.Done():
		<-ah.DoneCh
		<-ss.DoneCh
		return "", xerrors.Errorf("failed to get credentials within timeout (%s)", h.authTimeout)
	case token = <-ah.OutputCh:
		// will have to unwrap token if wrapped
		h.logger.Info("successfully authenticated")
	}

	if h.cacheEnabled {
		newTokenCh <- token
		select {
		case <-ctx.Done():
			<-ah.DoneCh
			<-ss.DoneCh
			return "", xerrors.Errorf("failed to write token to sink(s) within the timeout (%s)", h.authTimeout)
		case <-ss.DoneCh:
		}
	}
	cancel()
	<-ah.DoneCh
	<-ss.DoneCh
	close(newTokenCh)
	return token, nil
}
