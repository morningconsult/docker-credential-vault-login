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

type secretTable interface {
	GetPath(host string) (string, error)
}

// Options is used to configure a new Helper instance
type Options struct {
	Logger      hclog.Logger
	Client      *api.Client
	Secret      secretTable
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
	secret       secretTable
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
func (h *Helper) Get(serverURL string) (string, string, error) {
	secret, err := h.secret.GetPath(serverURL)
	if err != nil {
		h.logger.Error("error parsing registry path", "error", err)
		return "", "", xerrors.Errorf("error parsing registry path: %w", err)
	}

	if h.client.Token() != "" {
		// Get credentials with provided token
		return h.getCredentials(h.client.Token(), secret)
	}

	if h.cacheEnabled {
		cachedTokens := h.getCachedTokens()

		// Use any token to get credentials
		for _, token := range cachedTokens {
			var user, pass string

			// Get credentials
			if user, pass, err = h.getCredentials(token, secret); err == nil {
				return user, pass, nil
			}
		}
	}

	ctx := context.Background()

	token, err := h.authenticate(ctx)
	if err != nil {
		h.logger.Error("error authenticating to Vault", "error", err)
		return "", "", xerrors.Errorf("error authenticating to Vault: %w", err)
	}

	// Cache the token if caching is enabled
	if h.cacheEnabled {
		h.cacheToken(ctx, token)
	}

	// Get credentials
	return h.getCredentials(token, secret)
}

func (h *Helper) getCredentials(token, secret string) (string, string, error) {
	h.client.SetToken(token)

	creds, err := vault.GetCredentials(secret, h.client)
	if err != nil {
		errMsg := "error reading secret from Vault"
		h.logger.Error(errMsg, "error", err)

		return "", "", xerrors.Errorf("%s: %w", errMsg, err)
	}

	return creds.Username, creds.Password, nil
}

func (h *Helper) getCachedTokens() []string {
	clone, err := h.client.Clone()
	if err != nil {
		h.logger.Error("error cloning Vault API client", "error", err)
		return nil
	}

	// Get any cached tokens
	cachedTokens := cache.GetCachedTokens(h.logger.Named("cache"), h.authConfig.Sinks, clone)

	if len(cachedTokens) < 1 {
		h.logger.Info("no cached token(s) were read. Re-authenticating.")
		return nil
	}

	// Renew the cached tokens
	for _, token := range cachedTokens {
		if _, err = h.client.Auth().Token().RenewTokenAsSelf(token, 0); err != nil {
			h.logger.Error("error renewing cached token", "error", err)
		}
	}

	return cachedTokens
}

func (h *Helper) authenticate(ctx context.Context) (string, error) {
	method, err := vault.BuildAuthMethod(h.authConfig.Method, h.logger)
	if err != nil {
		return "", xerrors.Errorf("error creating auth method: %w", err)
	}

	h.client.ClearToken()

	ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
		Logger:  h.logger.Named("auth.handler"),
		Client:  h.client,
		WrapTTL: h.authConfig.Method.WrapTTL,
	})

	ctx, cancel := context.WithTimeout(ctx, h.authTimeout)
	defer cancel()

	go ah.Run(ctx, method)

	var token string
	select {
	case <-ctx.Done():
		<-ah.DoneCh
		return "", xerrors.Errorf("failed to get credentials within timeout (%s)", h.authTimeout)
	case token = <-ah.OutputCh:
		// will have to unwrap token if wrapped
		h.logger.Info("successfully authenticated")
	}
	cancel()
	<-ah.DoneCh

	return token, nil
}

func (h *Helper) cacheToken(ctx context.Context, token string) {
	sinks, err := vault.BuildSinks(h.authConfig.Sinks, h.logger, h.client)
	if err != nil {
		h.logger.Error("error building sinks; will not cache token", "error", err)
		return
	}

	if len(sinks) > 0 {
		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        h.logger.Named("sink.server"),
			Client:        h.client,
			ExitAfterAuth: true,
		})
		newTokenCh := make(chan string, 1)
		newTokenCh <- token
		ss.Run(ctx, newTokenCh, sinks)
		close(newTokenCh)
	}
}
