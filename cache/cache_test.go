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

package cache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/helper/dhutil"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/vault"
)

func TestGetCachedTokens_Wrapped(t *testing.T) {
	logger := hclog.NewNullLogger()

	coreConfig := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(hclog.Error),
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client
	// rootToken := client.Token()

	// Mount the auth backend
	err := client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Tune the mount
	err = client.Sys().TuneMount("auth/approle", api.MountConfigInput{
		DefaultLeaseTTL: "20s",
		MaxLeaseTTL:     "20s",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create role
	_, err = client.Logical().Write("auth/approle/role/role-period", map[string]interface{}{
		"period":   "20s",
		"policies": "dev-policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get role_id
	resp, err := client.Logical().Read("auth/approle/role/role-period/role-id")
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the role-id")
	}
	roleID, ok := resp.Data["role_id"].(string)
	if !ok {
		t.Fatal("could not convert 'role_id' to string")
	}

	// Get secret_id
	resp, err = client.Logical().Write("auth/approle/role/role-period/secret-id", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the secret-id")
	}
	secretID, ok := resp.Data["secret_id"].(string)
	if !ok {
		t.Fatal("could not convert 'secret_id' to string")
	}

	wrapTTL := 5 * time.Minute

	clone, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}
	clone.SetWrappingLookupFunc(func(string, string) string {
		return wrapTTL.String()
	})

	secret, err := clone.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		t.Fatal(err)
	}

	filename := "testdata/token-wrapped.json"

	randomUUID := func() string {
		id, err := uuid.GenerateUUID()
		if err != nil {
			t.Fatalf("error generating UUID: %v", err)
		}
		return id
	}

	cases := []struct {
		name   string
		data   interface{}
		sinks  []*config.Sink
		tokens int
	}{
		{
			"wrapped-token",
			secret.WrapInfo,
			[]*config.Sink{
				{
					Type:    "file",
					WrapTTL: wrapTTL,
					Config: map[string]interface{}{
						"path": filename,
					},
				},
			},
			1,
		},
		{
			"unexpected-json-format",
			`{"not": "secret"}`,
			[]*config.Sink{
				{
					WrapTTL: wrapTTL,
					Config: map[string]interface{}{
						"path": filename,
					},
				},
			},
			0,
		},
		{
			"invalid-token",
			&api.SecretWrapInfo{
				Token: randomUUID(),
			},
			[]*config.Sink{
				{
					WrapTTL: wrapTTL,
					Config: map[string]interface{}{
						"path": filename,
					},
				},
			},
			0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.data)
			if err != nil {
				t.Fatal(err)
			}

			if err = ioutil.WriteFile(filename, data, 0o644); err != nil {
				t.Fatal(err)
			}

			defer os.Remove(filename)

			tokens := GetCachedTokens(logger, tc.sinks, client)
			if len(tokens) != tc.tokens {
				t.Fatalf("Expected %d token(s), got %d tokens", tc.tokens, len(tokens))
			}
			if tc.tokens < 1 {
				return
			}
			client.SetToken(tokens[0])
			lookup, err := client.Auth().Token().LookupSelf()
			if err != nil {
				t.Fatal(err)
			}
			ttl, err := lookup.TokenTTL()
			if err != nil {
				t.Fatal(err)
			}
			if ttl < 1 {
				t.Fatal("Token is expired")
			}
		})
	}
}

func TestGetCachedTokens_Plain(t *testing.T) {
	cases := []struct {
		name   string
		sinks  []*config.Sink
		tokens int
	}{
		{
			"plain-token",
			[]*config.Sink{
				{
					Type: "file",
					Config: map[string]interface{}{
						"path": "testdata/token-plain.txt",
					},
				},
			},
			1,
		},
		{
			"no-path",
			[]*config.Sink{
				{
					Config: map[string]interface{}{}, // no path
				},
			},
			0,
		},
		{
			"path-not-string",
			[]*config.Sink{
				{
					Config: map[string]interface{}{
						"path": map[string]interface{}{
							"hello": "world",
						},
					},
				},
			},
			0,
		},
		{
			"file-doesnt-exist",
			[]*config.Sink{
				{
					Config: map[string]interface{}{
						"path": "testdata/file-doesnt-exist.txt",
					},
				},
			},
			0,
		},
	}

	logger := hclog.NewNullLogger()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokens := GetCachedTokens(logger, tc.sinks, nil)
			if len(tokens) != tc.tokens {
				t.Fatalf("Expected %d token(s), got %d tokens", tc.tokens, len(tokens))
			}
			if tc.tokens < 1 {
				return
			}
			if _, err := uuid.ParseUUID(tokens[0]); err != nil {
				t.Fatalf("Token is not a valid UUID: %v", err)
			}
		})
	}
}

func TestGetCachedTokens_Encrypted(t *testing.T) {
	base64Decode := func(s string) []byte {
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("error base64-decoding string: %v", err)
		}
		return data
	}

	privateKeyData, err := ioutil.ReadFile("testdata/dh-private-key.json")
	if err != nil {
		t.Fatal(err)
	}
	pk := new(privateKeyInfo)
	if err = json.Unmarshal(privateKeyData, pk); err != nil {
		t.Fatal(err)
	}
	privateKey := pk.Curve25519PrivateKey

	resp := &dhutil.Envelope{
		Curve25519PublicKey: base64Decode("jHJcqNbAydq9NkvNud86vh2AOv0fPRdrLtCoEoxwTVc="),
		Nonce:               base64Decode("qzpQihDHElzW0mf1"),
		EncryptedPayload:    base64Decode("GVH1YTtDw7pWpMPs1GQKRrl2CRuw5M54mtPuYWJuLMY3tYNHwmN8vnwZ4QcmcKg2KcuaWw=="),
	}

	aesKey, err := dhutil.GenerateSharedSecret(privateKey, resp.Curve25519PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(aesKey) == 0 {
		t.Fatal("derived AES key is empty")
	}

	data, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte("foobar"))
	if err != nil {
		t.Fatal(err)
	}

	expected := string(data)

	cases := []struct {
		name      string
		tokenFile string
		tokenData interface{}
		pkFile    string
		pkData    interface{}
		sinks     []*config.Sink
		tokens    int
	}{
		{
			"encrypted-token",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					Type:   "file",
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			1,
		},
		{
			"invalid-token-json",
			"testdata/token-encrypted.json",
			`{"not": "valid"}`,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			0,
		},
		{
			"no-private-key",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path": "testdata/token-encrypted.json",
					},
				},
			},
			0,
		},
		{
			"private-key-file-not-string",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path": "testdata/token-encrypted.json",
						"dh_priv": map[string]interface{}{
							"hello": "world",
						},
					},
				},
			},
			0,
		},
		{
			"cannot-open-private-key",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/does-not-exist.json",
					},
				},
			},
			0,
		},
		{
			"private-key-malformed-json",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			`asdf`,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			0,
		},
		{
			"private-key-empty",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			&privateKeyInfo{
				Curve25519PrivateKey: []byte(""),
			},
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			0,
		},
		{
			"wrong-aad",
			"testdata/token-encrypted.json",
			resp,
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "barfoo",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			0,
		},
		{
			"malformed-token",
			"testdata/token-encrypted.json",
			&dhutil.Envelope{
				Curve25519PublicKey: []byte("not a token!"),
				Nonce:               resp.Nonce,
				EncryptedPayload:    resp.EncryptedPayload,
			},
			"testdata/temp-priv-key.json",
			pk,
			[]*config.Sink{
				{
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":    "testdata/token-encrypted.json",
						"dh_priv": "testdata/temp-priv-key.json",
					},
				},
			},
			0,
		},
	}

	logger := hclog.NewNullLogger()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode token and write file
			data, err := json.Marshal(tc.tokenData)
			if err != nil {
				t.Fatal(err)
			}
			if err = ioutil.WriteFile(tc.tokenFile, data, 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tc.tokenFile)

			// Encode private key and write file
			data, err = json.Marshal(tc.pkData)
			if err != nil {
				t.Fatal(err)
			}
			if err = ioutil.WriteFile(tc.pkFile, data, 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tc.pkFile)

			tokens := GetCachedTokens(logger, tc.sinks, nil)
			if len(tokens) != tc.tokens {
				t.Fatalf("Expected %d token(s), got %d tokens", tc.tokens, len(tokens))
			}
			if tc.tokens < 1 {
				return
			}
			if tokens[0] != expected {
				t.Fatalf("Tokens differ:\n%v", cmp.Diff(tokens[0], expected))
			}
		})
	}
}

func TestGetCachedTokens_EnvVar(t *testing.T) {
	base64Decode := func(s string) []byte {
		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("error base64-decoding string: %v", err)
		}
		return data
	}

	privateKeyData, err := ioutil.ReadFile("testdata/dh-private-key.json")
	if err != nil {
		t.Fatal(err)
	}
	privateKeyInfo := new(privateKeyInfo)
	if err = json.Unmarshal(privateKeyData, privateKeyInfo); err != nil {
		t.Fatal(err)
	}
	privateKey := privateKeyInfo.Curve25519PrivateKey

	resp := &dhutil.Envelope{
		Curve25519PublicKey: base64Decode("jHJcqNbAydq9NkvNud86vh2AOv0fPRdrLtCoEoxwTVc="),
		Nonce:               base64Decode("qzpQihDHElzW0mf1"),
		EncryptedPayload:    base64Decode("GVH1YTtDw7pWpMPs1GQKRrl2CRuw5M54mtPuYWJuLMY3tYNHwmN8vnwZ4QcmcKg2KcuaWw=="),
	}

	aesKey, err := dhutil.GenerateSharedSecret(privateKey, resp.Curve25519PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(aesKey) == 0 {
		t.Fatal("derived AES key is empty")
	}

	data, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte("foobar"))
	if err != nil {
		t.Fatal(err)
	}

	expected := string(data)

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if err = ioutil.WriteFile("testdata/token-encrypted.json", data, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testdata/token-encrypted.json")

	cases := []struct {
		name   string
		envKey string
		envVal string
		sinks  []*config.Sink
		tokens int
	}{
		{
			"valid-base64",
			"DCVL_DH_PRIV_KEY_1",
			base64.StdEncoding.EncodeToString(privateKey),
			[]*config.Sink{
				{
					Type:   "file",
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":        "testdata/token-encrypted.json",
						"dh_priv_env": "DCVL_DH_PRIV_KEY_1",
					},
				},
			},
			1,
		},
		{
			"invalid-base64",
			"DCVL_DH_PRIV_KEY_1",
			"not valid base64!",
			[]*config.Sink{
				{
					Type:   "file",
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path":        "testdata/token-encrypted.json",
						"dh_priv_env": "DCVL_DH_PRIV_KEY_1",
					},
				},
			},
			0,
		},
		{
			"old-env-var-only",
			EnvDiffieHellmanPrivateKey,
			base64.StdEncoding.EncodeToString(privateKey),
			[]*config.Sink{
				{
					Type:   "file",
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path": "testdata/token-encrypted.json",
					},
				},
			},
			1,
		},
		{
			"no-env-vars",
			"",
			"",
			[]*config.Sink{
				{
					Type:   "file",
					DHType: "curve25519",
					AAD:    "foobar",
					Config: map[string]interface{}{
						"path": "testdata/token-encrypted.json",
					},
				},
			},
			0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv(tc.envKey, tc.envVal)
			defer os.Unsetenv(tc.envKey)

			tokens := GetCachedTokens(hclog.NewNullLogger(), tc.sinks, nil)
			if len(tokens) != tc.tokens {
				t.Fatalf("Expected %d token(s), got %d tokens", tc.tokens, len(tokens))
			}
			if tc.tokens < 1 {
				return
			}
			if tokens[0] != expected {
				t.Fatalf("Tokens differ:\n%v", cmp.Diff(tokens[0], expected))
			}
		})
	}
}

func TestUnwrapToken(t *testing.T) {
	cases := []struct {
		name        string
		token       string
		unwrap      unwrapFunc
		expectErr   string
		expectToken string
	}{
		{
			name:        "bad-json",
			token:       "not a json!",
			unwrap:      nil,
			expectErr:   "error JSON-decoding TTL-wrapped secret: invalid character 'o' in literal null (expecting 'u')",
			expectToken: "",
		},
		{
			name:  "unwrap-error",
			token: `{"token":"s.2zOhQugrfYqd6E1ccCyNBIHv"}`,
			unwrap: func(_ string) (*api.Secret, error) {
				return nil, errors.New("oops")
			},
			expectErr:   "error unwrapping token: oops",
			expectToken: "",
		},
		{
			name:  "token-id-error",
			token: `{"token":"s.2zOhQugrfYqd6E1ccCyNBIHv"}`,
			unwrap: func(_ string) (*api.Secret, error) {
				return &api.Secret{
					Data: map[string]interface{}{
						"id": 123613246,
					},
				}, nil
			},
			expectErr:   "error reading token from Vault response: token found but in the wrong format",
			expectToken: "",
		},
		{
			name:  "token-from-secret-data",
			token: `{"token":"s.2zOhQugrfYqd6E1ccCyNBIHv"}`,
			unwrap: func(_ string) (*api.Secret, error) {
				return &api.Secret{
					Data: map[string]interface{}{
						"token": "s.2zOhQugrfYqd6E1ccCyNBIHv",
					},
				}, nil
			},
			expectErr:   "",
			expectToken: "s.2zOhQugrfYqd6E1ccCyNBIHv",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotToken, err := unwrapToken(tc.token, tc.unwrap)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if err.Error() != tc.expectErr {
					t.Errorf("Expected error %q, got error %q", tc.expectErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(gotToken, tc.expectToken) {
				t.Errorf("Tokens differ:\n%v", cmp.Diff(tc.expectToken, gotToken))
			}
		})
	}
}

func TestReadDHPrivateKey(t *testing.T) {
	expectKey, err := base64.StdEncoding.DecodeString("NXAnojBsGvT9UMkLPssHdrqEOoqxBFV+c3Bf9YP8VcM=")
	if err != nil {
		t.Fatalf("error base64-decoding key: %v", err)
	}

	cases := []struct {
		name      string
		config    map[string]interface{}
		expectErr string
		expectKey []byte
	}{
		{
			name:      "no-path-to-private-key-in-config",
			config:    nil,
			expectErr: "no Diffie-Hellman private key provided",
			expectKey: nil,
		},
		{
			name: "dh-private-key-not-string",
			config: map[string]interface{}{
				"dh_priv": 12345,
			},
			expectErr: "no Diffie-Hellman private key provided",
			expectKey: nil,
		},
		{
			name: "dh-private-key-file-does-not-exist",
			config: map[string]interface{}{
				"dh_priv": "testdata/does-not-exist.json",
			},
			expectErr: "error opening 'dh_priv' file testdata/does-not-exist.json: open testdata/does-not-exist.json: no such file or directory", // nolint: lll
			expectKey: nil,
		},
		{
			name: "dh-private-key-malformed",
			config: map[string]interface{}{
				"dh_priv": "testdata/dh-private-key-malformed.json",
			},
			expectErr: "error JSON-decoding file testdata/dh-private-key-malformed.json: json: cannot unmarshal string into Go value of type cache.privateKeyInfo", // nolint: lll
			expectKey: nil,
		},
		{
			name: "dh-private-key-empty",
			config: map[string]interface{}{
				"dh_priv": "testdata/dh-private-key-empty.json",
			},
			expectErr: "field 'curve25519_private_key' of file testdata/dh-private-key-empty.json is empty",
			expectKey: nil,
		},
		{
			name: "success",
			config: map[string]interface{}{
				"dh_priv": "testdata/dh-private-key.json",
			},
			expectErr: "",
			expectKey: expectKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := readDHPrivateKey(tc.config)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if err.Error() != tc.expectErr {
					t.Errorf("Expected error %q, got error %q", tc.expectErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(gotKey, tc.expectKey) {
				t.Errorf("Keys differ:\n%v", cmp.Diff(tc.expectKey, gotKey))
			}
		})
	}
}

func TestDecryptToken(t *testing.T) {
	noop := func() {}

	cases := []struct {
		name        string
		pre         func()
		post        func()
		token       string
		aad         string
		config      map[string]interface{}
		expectErr   string
		expectToken string
	}{
		{
			name:        "bad-json",
			pre:         noop,
			post:        noop,
			token:       `not a json`,
			aad:         "",
			config:      nil,
			expectErr:   "error JSON-decoding file sink: invalid character 'o' in literal null (expecting 'u')",
			expectToken: "",
		},
		{
			name: "error-reading-key-from-env",
			pre: func() {
				// This is to check backwards compatibility - it ensures that
				// the DCVL_DH_PRIV_KEY environment variable takes precedence
				// over any other environment variables
				os.Setenv(EnvDiffieHellmanPrivateKey, "i should be base64")
				os.Setenv("DCVL_DH_PRIV_KEY_1", "kYU15pdT5zjjJ9aLD3eG+1jljySQn47c8W+IHTgJYAA=")
			},
			post: func() {
				os.Unsetenv(EnvDiffieHellmanPrivateKey)
				os.Unsetenv("DCVL_DH_PRIV_KEY_1")
			},
			token:       `{"curve25519_public_key":""}`,
			aad:         "",
			config:      map[string]interface{}{"dh_priv_env": "DCVL_DH_PRIV_KEY_1"},
			expectErr:   "error reading Diffie-Hellman private key file: error base64-decoding DCVL_DH_PRIV_KEY: illegal base64 data at input byte 1",
			expectToken: "",
		},
		{
			name:        "reads-private-key-from-env",
			pre:         func() { os.Setenv("DCVL_DH_PRIV_KEY_1", "kYU15pdT5zjjJ9aLD3eG+1jljySQn47c8W+IHTgJYAA=") },
			post:        func() { os.Unsetenv("DCVL_DH_PRIV_KEY_1") },
			token:       `{"curve25519_public_key":"BzaaB2oB3c2aOcPB6PocpKjEpOtvhGRTl8sUFu9OaH0=","nonce":"guhCxCtngC9OnAjj","encrypted_payload":"53318eHfcsz3jQnwTuGKH+VpaW7d0oA7KL59DwfzjVjImZLcD4k8t6KWTSTXi2Wwvy2T+n8aUVjkirxlYCALYYFIRuMGvAChDbAk7Sdg+CJJ/dDS5ifF2+ax/IHe7V+p4sdPN2HtMDFMosDK2MQvj9TxLdPg21n6LrVR40lkRJlXzVT9pNKUeXPXK3WxDCpnIDwnBeoxCnsj9ujFkj/3lFKdoW7GUK+93d87oUKC/BKouTQQfWXgtGS6d9zOkhM/ppg+57q54TlRyieLBtM56MYINGeBMKY="}`,
			aad:         "TESTAAD",
			config:      map[string]interface{}{"dh_priv_env": "DCVL_DH_PRIV_KEY_1"},
			expectErr:   "",
			expectToken: "{\"token\":\"s.jig43pxA52Y2xhiahImw3HQv\",\"accessor\":\"9l9LCryNuBMuTyWTbmZeFhSx\",\"ttl\":300,\"creation_time\":\"2019-09-25T15:31:25.646033046-04:00\",\"creation_path\":\"sys/wrapping/wrap\",\"wrapped_accessor\":\"\"}\n",
		},
		{
			name:        "reads-private-key-from-config",
			pre:         noop,
			post:        noop,
			token:       `{"curve25519_public_key":"BzaaB2oB3c2aOcPB6PocpKjEpOtvhGRTl8sUFu9OaH0=","nonce":"guhCxCtngC9OnAjj","encrypted_payload":"53318eHfcsz3jQnwTuGKH+VpaW7d0oA7KL59DwfzjVjImZLcD4k8t6KWTSTXi2Wwvy2T+n8aUVjkirxlYCALYYFIRuMGvAChDbAk7Sdg+CJJ/dDS5ifF2+ax/IHe7V+p4sdPN2HtMDFMosDK2MQvj9TxLdPg21n6LrVR40lkRJlXzVT9pNKUeXPXK3WxDCpnIDwnBeoxCnsj9ujFkj/3lFKdoW7GUK+93d87oUKC/BKouTQQfWXgtGS6d9zOkhM/ppg+57q54TlRyieLBtM56MYINGeBMKY="}`,
			aad:         "TESTAAD",
			config:      map[string]interface{}{"dh_priv": "testdata/dh-private-key-2.json"},
			expectErr:   "",
			expectToken: "{\"token\":\"s.jig43pxA52Y2xhiahImw3HQv\",\"accessor\":\"9l9LCryNuBMuTyWTbmZeFhSx\",\"ttl\":300,\"creation_time\":\"2019-09-25T15:31:25.646033046-04:00\",\"creation_path\":\"sys/wrapping/wrap\",\"wrapped_accessor\":\"\"}\n",
		},
		{
			name:        "error-generating-shared-keys",
			pre:         noop,
			post:        noop,
			token:       `{"curve25519_public_key":"","nonce":"guhCxCtngC9OnAjj","encrypted_payload":"53318eHfcsz3jQnwTuGKH+VpaW7d0oA7KL59DwfzjVjImZLcD4k8t6KWTSTXi2Wwvy2T+n8aUVjkirxlYCALYYFIRuMGvAChDbAk7Sdg+CJJ/dDS5ifF2+ax/IHe7V+p4sdPN2HtMDFMosDK2MQvj9TxLdPg21n6LrVR40lkRJlXzVT9pNKUeXPXK3WxDCpnIDwnBeoxCnsj9ujFkj/3lFKdoW7GUK+93d87oUKC/BKouTQQfWXgtGS6d9zOkhM/ppg+57q54TlRyieLBtM56MYINGeBMKY="}`,
			aad:         "TESTAAD",
			config:      map[string]interface{}{"dh_priv": "testdata/dh-private-key.json"},
			expectErr:   "error creating AES-GCM key: invalid public key length: 0",
			expectToken: "",
		},
		{
			name:        "error-decrypting",
			pre:         noop,
			post:        noop,
			token:       `{"curve25519_public_key":"BzaaB2oB3c2aOcPB6PocpKjEpOtvhGRTl8sUFu9OaH0=","nonce":"guhCxCtngC9OnAjj","encrypted_payload":"53318eHfcsz3jQnwTuGKH+VpaW7d0oA7KL59DwfzjVjImZLcD4k8t6KWTSTXi2Wwvy2T+n8aUVjkirxlYCALYYFIRuMGvAChDbAk7Sdg+CJJ/dDS5ifF2+ax/IHe7V+p4sdPN2HtMDFMosDK2MQvj9TxLdPg21n6LrVR40lkRJlXzVT9pNKUeXPXK3WxDCpnIDwnBeoxCnsj9ujFkj/3lFKdoW7GUK+93d87oUKC/BKouTQQfWXgtGS6d9zOkhM/ppg+57q54TlRyieLBtM56MYINGeBMKY="}`,
			aad:         "TESTAADAAA", // Wrong AAD
			config:      map[string]interface{}{"dh_priv": "testdata/dh-private-key-2.json"},
			expectErr:   "error decrypting token: cipher: message authentication failed",
			expectToken: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.pre()
			defer tc.post()

			gotToken, err := decryptToken(tc.token, tc.aad, tc.config)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatal("expected an error")
				}
				if err.Error() != tc.expectErr {
					t.Errorf("Expected error %q, got error %q", tc.expectErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(gotToken, tc.expectToken) {
				t.Errorf("Tokens differ:\n%v", cmp.Diff(tc.expectToken, gotToken))
			}
		})
	}
}
