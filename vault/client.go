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
	"context"
	"strings"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/morningconsult/docker-credential-vault-login/cache"
	"golang.org/x/xerrors"
)

const defaultAuthTimeout = 10 * time.Second

// Client is used to interface with Vault
type Client struct {
	client      *api.Client
	authTimeout time.Duration
	authConfig  *config.AutoAuth
	logger      hclog.Logger
}

// ClientOptions is used to configure the Client
type ClientOptions struct {
	Logger      hclog.Logger
	Client      *api.Client
	AuthTimeout time.Duration
	AuthConfig  *config.AutoAuth
}

// NewClient creates a new instance of Client
func NewClient(opts ClientOptions) Client {
	if opts.AuthTimeout == 0 {
		opts.AuthTimeout = defaultAuthTimeout
	}

	if opts.Logger == nil {
		opts.Logger = hclog.Default()
	}

	return Client{
		logger:      opts.Logger,
		client:      opts.Client,
		authTimeout: opts.AuthTimeout,
		authConfig:  opts.AuthConfig,
	}
}

// GetCredentials uses the Vault client to read the secret at
// path
func (c Client) GetCredentials(token, path string) (string, string, error) {
	var (
		username, password string
		ok                 bool
		missingSecrets     []string
	)

	c.client.SetToken(token)

	secret, err := c.client.Logical().Read(path)
	if err != nil {
		return "", "", xerrors.Errorf("error reading secret: %v", err)
	}

	if secret == nil {
		return "", "", xerrors.Errorf("No secret found in Vault at path %q", path)
	}

	creds := secret.Data

	// Check for metadata in the response which will only exist if this is a kv-v2 mount
	// https://www.vaultproject.io/api/secret/kv/kv-v2.html#sample-response-1
	_, isKvv2 := secret.Data["metadata"].(map[string]interface{})
	if isKvv2 {
		creds = secret.Data["data"].(map[string]interface{})
	}

	if username, ok = creds["username"].(string); !ok || username == "" {
		missingSecrets = append(missingSecrets, "username")
	}

	if password, ok = creds["password"].(string); !ok || password == "" {
		missingSecrets = append(missingSecrets, "password")
	}

	if len(missingSecrets) > 0 {
		return "", "", xerrors.Errorf("No %s found in Vault at path %q", strings.Join(missingSecrets, " or "), path)
	}

	return username, password, nil
}

// Authenticate authenticates to Vault to obtain a new Vault token.
func (c Client) Authenticate(ctx context.Context) (string, error) {
	method, err := buildAuthMethod(c.authConfig.Method, c.logger)
	if err != nil {
		return "", xerrors.Errorf("error creating auth method: %w", err)
	}

	c.client.ClearToken()

	ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
		Logger:  c.logger.Named("auth.handler"),
		Client:  c.client,
		WrapTTL: c.authConfig.Method.WrapTTL,
	})

	ctx, cancel := context.WithTimeout(ctx, c.authTimeout)
	defer cancel()

	go ah.Run(ctx, method)

	var token string
	select {
	case <-ctx.Done():
		<-ah.DoneCh
		return "", xerrors.Errorf("failed to get credentials within timeout (%s)", c.authTimeout)
	case token = <-ah.OutputCh:
		// will have to unwrap token if wrapped
		c.logger.Info("successfully authenticated")
	}
	cancel()
	<-ah.DoneCh

	return token, nil
}

// GetCachedTokens looks up all cached tokens based on the configuration
// file and attempts to renew them.
func (c Client) GetCachedTokens() []string {
	clone, err := c.client.Clone()
	if err != nil {
		c.logger.Error("error cloning Vault API client", "error", err)
		return nil
	}

	// Get any cached tokens
	cachedTokens := cache.GetCachedTokens(c.logger.Named("cache"), c.authConfig.Sinks, clone)

	// Renew the cached tokens
	for _, token := range cachedTokens {
		if _, err = c.client.Auth().Token().RenewTokenAsSelf(token, 0); err != nil {
			c.logger.Error("error renewing cached token", "error", err)
		}
	}

	return cachedTokens
}

// CacheToken caches the given token according to your
// configuration file.
func (c Client) CacheToken(ctx context.Context, token string) {
	sinks, err := buildSinks(c.authConfig.Sinks, c.logger, c.client)
	if err != nil {
		c.logger.Error("error building sinks; will not cache token", "error", err)
		return
	}

	if len(sinks) > 0 {
		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        c.logger.Named("sink.server"),
			Client:        c.client,
			ExitAfterAuth: true,
		})
		newTokenCh := make(chan string, 1)
		newTokenCh <- token
		ss.Run(ctx, newTokenCh, sinks)
		close(newTokenCh)
	}
}
