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
	"sync/atomic"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
)

func TestHelper_Get(t *testing.T) {
	logger := hclog.NewNullLogger()
	numCalls := new(int32)
	*numCalls = 0

	cases := []struct {
		name            string
		getPath         func(string) (string, error)
		getCredentials  func(string, string) (string, string, error)
		authenticate    func(context.Context) (string, error)
		getCachedTokens func() []string
		cacheToken      func(context.Context, string)
		cacheEnabled    bool
		token           string
		expectErr       string
		expectUser      string
		expectPass      string
		expectNumCalls  int32
	}{
		{
			name: "error-getting-secret",
			getPath: func(_ string) (string, error) {
				return "", errors.New("error getting secret")
			},
			expectErr: "error parsing registry path: error getting secret",
		},
		{
			name: "gets-credentials-no-token-no-cache",
			getCredentials: func(_, _ string) (string, string, error) {
				atomic.AddInt32(numCalls, 1)
				return "test@user.com", "password", nil
			},
			expectUser:     "test@user.com",
			expectPass:     "password",
			expectNumCalls: 1,
		},
		{
			name: "gets-credentials-with-token",
			getCredentials: func(token, _ string) (string, string, error) {
				atomic.AddInt32(numCalls, 1)
				if token != "4f13d9dc-2460-45fd-a702-f2ec51db7e6f" {
					t.Errorf("Expected token %q, got token %q", "4f13d9dc-2460-45fd-a702-f2ec51db7e6f", token)
				}
				return "test@user.com", "password", nil
			},
			token:          "4f13d9dc-2460-45fd-a702-f2ec51db7e6f",
			expectUser:     "test@user.com",
			expectPass:     "password",
			expectNumCalls: 1,
		},
		{
			name: "gets-credentials-from-cache",
			getCredentials: func(token, _ string) (string, string, error) {
				atomic.AddInt32(numCalls, 1)
				if token == "4b663b8d-2485-456a-8e2a-fcdad0b4af4d" {
					return "test@user.com", "password", nil
				}
				return "", "", errors.New("failed to get cached token")
			},
			getCachedTokens: func() []string {
				return []string{
					"4dab504a-3633-4b11-b6fd-497d0ea79699",
					"4b663b8d-2485-456a-8e2a-fcdad0b4af4d",
				}
			},
			cacheEnabled:   true,
			expectUser:     "test@user.com",
			expectPass:     "password",
			expectNumCalls: 2,
		},
		{
			name: "fails-to-get-credentials-with-cached-tokens",
			getCredentials: func(token, _ string) (string, string, error) {
				atomic.AddInt32(numCalls, 1)
				if token == "2f9a58fc-14db-4eed-840e-7de09412af62" {
					return "test@user.com", "password", nil
				}
				return "", "", errors.New("failed to get cached token")
			},
			getCachedTokens: func() []string {
				return []string{
					"4dab504a-3633-4b11-b6fd-497d0ea79699",
					"4b663b8d-2485-456a-8e2a-fcdad0b4af4d",
				}
			},
			authenticate: func(_ context.Context) (string, error) {
				return "2f9a58fc-14db-4eed-840e-7de09412af62", nil
			},
			cacheEnabled:   true,
			expectUser:     "test@user.com",
			expectPass:     "password",
			expectNumCalls: 3,
		},
		{
			name: "caches-token-after-auth",
			getCredentials: func(token, _ string) (string, string, error) {
				if token == "2f9a58fc-14db-4eed-840e-7de09412af62" {
					return "test@user.com", "password", nil
				}
				return "", "", errors.New("failed to get cached token")
			},
			authenticate: func(_ context.Context) (string, error) {
				return "2f9a58fc-14db-4eed-840e-7de09412af62", nil
			},
			cacheToken: func(_ context.Context, token string) {
				if token != "2f9a58fc-14db-4eed-840e-7de09412af62" {
					t.Errorf("Expected token %q, got token %q", "2f9a58fc-14db-4eed-840e-7de09412af62", token)
				}
				atomic.AddInt32(numCalls, 1)
			},
			cacheEnabled:   true,
			expectUser:     "test@user.com",
			expectPass:     "password",
			expectNumCalls: 1,
		},
		{
			name: "error-authenticating",
			authenticate: func(_ context.Context) (string, error) {
				return "", errors.New("error authenticating")
			},
			expectErr: "error authenticating to Vault: error authenticating",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() { *numCalls = 0 }()

			table := mockSecretTable{
				mockSecretTableConfig{getPath: tc.getPath},
			}
			client := mockClient{
				mockClientConfig{
					getCredentials:  tc.getCredentials,
					authenticate:    tc.authenticate,
					getCachedTokens: tc.getCachedTokens,
					cacheToken:      tc.cacheToken,
				},
			}
			helper := Helper{
				logger:       logger,
				client:       client,
				secret:       table,
				cacheEnabled: tc.cacheEnabled,
				token:        tc.token,
			}
			gotUser, gotPass, err := helper.Get("")
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("Expected an error")
				}
				gotErr := err.Error()
				if gotErr != tc.expectErr {
					t.Fatalf("Expected error:\n%s\nGot error:\n%s", tc.expectErr, gotErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotUser != tc.expectUser {
				t.Errorf("Expected user %q, got user %q", tc.expectUser, gotUser)
			}
			if gotPass != tc.expectPass {
				t.Errorf("Expected password %q, got password %q", tc.expectPass, gotPass)
			}
			if *numCalls != tc.expectNumCalls {
				t.Errorf("Expected GetCredentials to be called %d time(s), but it was called %d time(s)", tc.expectNumCalls, *numCalls)
			}
		})
	}
}

type mockClientConfig struct {
	getCredentials  func(token, path string) (string, string, error)
	authenticate    func(ctx context.Context) (string, error)
	getCachedTokens func() []string
	cacheToken      func(ctx context.Context, token string)
}

type mockClient struct {
	cfg mockClientConfig
}

func (m mockClient) GetCredentials(token, path string) (string, string, error) {
	if m.cfg.getCredentials == nil {
		return "", "", nil
	}
	return m.cfg.getCredentials(token, path)
}

func (m mockClient) Authenticate(ctx context.Context) (string, error) {
	if m.cfg.authenticate == nil {
		return "", nil
	}
	return m.cfg.authenticate(ctx)
}

func (m mockClient) GetCachedTokens() []string {
	if m.cfg.getCachedTokens == nil {
		return nil
	}
	return m.cfg.getCachedTokens()
}

func (m mockClient) CacheToken(ctx context.Context, token string) {
	if m.cfg.cacheToken == nil {
		return
	}
	m.cfg.cacheToken(ctx, token)
}

type mockSecretTableConfig struct {
	getPath func(string) (string, error)
}

type mockSecretTable struct {
	cfg mockSecretTableConfig
}

func (m mockSecretTable) GetPath(path string) (string, error) {
	if m.cfg.getPath == nil {
		return "", nil
	}
	return m.cfg.getPath(path)
}
