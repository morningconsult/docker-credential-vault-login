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

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/xerrors"
)

var (
	errNotImplemented = errors.New("not implemented")
)

type secretTable interface {
	GetPath(host string) (string, error)
}

type client interface {
	GetCredentials(token, path string) (string, string, error)
	Authenticate(ctx context.Context) (string, error)
	GetCachedTokens() []string
	CacheToken(ctx context.Context, token string)
}

// Options is used to configure a new Helper instance
type Options struct {
	Logger      hclog.Logger
	Client      client
	Secret      secretTable
	EnableCache bool
	Token       string
}

// Helper implements a Docker credential helper which will
// fetch Docker credentials from Vault and pass them to
// the Docker daemon in order to authenticate to a private
// Docker registry
type Helper struct {
	logger       hclog.Logger
	client       client
	secret       secretTable
	cacheEnabled bool
	token        string
}

// New creates a new Helper instance
func New(opts Options) *Helper {
	return &Helper{
		logger:       opts.Logger,
		client:       opts.Client,
		secret:       opts.Secret,
		cacheEnabled: opts.EnableCache,
		token:        opts.Token,
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

	if h.token != "" {
		return h.getCredentials(h.token, secret)
	}

	if h.cacheEnabled {
		// If cache is enabled, get all cached Vault tokens
		cachedTokens := h.client.GetCachedTokens()

		for _, token := range cachedTokens {
			var user, pass string

			// Get credentials
			if user, pass, err = h.getCredentials(token, secret); err == nil {
				return user, pass, nil
			}
		}
	}

	ctx := context.Background()

	token, err := h.client.Authenticate(ctx)
	if err != nil {
		h.logger.Error("error authenticating to Vault", "error", err)
		return "", "", xerrors.Errorf("error authenticating to Vault: %w", err)
	}

	if h.cacheEnabled {
		h.client.CacheToken(ctx, token)
	}

	return h.getCredentials(token, secret)
}

func (h *Helper) getCredentials(token, secret string) (string, string, error) {
	username, password, err := h.client.GetCredentials(token, secret)
	if err != nil {
		h.logger.Error("error getting credentials", "error", err)
		return "", "", xerrors.Errorf("error getting credentials: %w", err)
	}

	return username, password, nil
}
