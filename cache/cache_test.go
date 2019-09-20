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
	resp, err := client.Logical().Write("auth/approle/role/role-period", map[string]interface{}{
		"period":   "20s",
		"policies": "dev-policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get role_id
	resp, err = client.Logical().Read("auth/approle/role/role-period/role-id")
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
				&config.Sink{
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
				&config.Sink{
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
				&config.Sink{
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

			if err = ioutil.WriteFile(filename, data, 0644); err != nil {
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
				&config.Sink{
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
				&config.Sink{
					Config: map[string]interface{}{}, // no path
				},
			},
			0,
		},
		{
			"path-not-string",
			[]*config.Sink{
				&config.Sink{
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
				&config.Sink{
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
	privateKeyInfo := new(PrivateKeyInfo)
	if err = json.Unmarshal(privateKeyData, privateKeyInfo); err != nil {
		t.Fatal(err)
	}
	privateKey := privateKeyInfo.Curve25519PrivateKey

	resp := &dhutil.Envelope{
		Curve25519PublicKey: base64Decode("jHJcqNbAydq9NkvNud86vh2AOv0fPRdrLtCoEoxwTVc="),
		Nonce:               base64Decode("qzpQihDHElzW0mf1"),
		EncryptedPayload:    base64Decode("GVH1YTtDw7pWpMPs1GQKRrl2CRuw5M54mtPuYWJuLMY3tYNHwmN8vnwZ4QcmcKg2KcuaWw=="),
	}

	aesKey, err := dhutil.GenerateSharedKey(privateKey, resp.Curve25519PublicKey)
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
				&config.Sink{
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
			&PrivateKeyInfo{
				Curve25519PrivateKey: []byte(""),
			},
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			privateKeyInfo,
			[]*config.Sink{
				&config.Sink{
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
			if err = ioutil.WriteFile(tc.tokenFile, data, 0644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tc.tokenFile)

			// Encode private key and write file
			data, err = json.Marshal(tc.pkData)
			if err != nil {
				t.Fatal(err)
			}
			if err = ioutil.WriteFile(tc.pkFile, data, 0644); err != nil {
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
	privateKeyInfo := new(PrivateKeyInfo)
	if err = json.Unmarshal(privateKeyData, privateKeyInfo); err != nil {
		t.Fatal(err)
	}
	privateKey := privateKeyInfo.Curve25519PrivateKey

	resp := &dhutil.Envelope{
		Curve25519PublicKey: base64Decode("jHJcqNbAydq9NkvNud86vh2AOv0fPRdrLtCoEoxwTVc="),
		Nonce:               base64Decode("qzpQihDHElzW0mf1"),
		EncryptedPayload:    base64Decode("GVH1YTtDw7pWpMPs1GQKRrl2CRuw5M54mtPuYWJuLMY3tYNHwmN8vnwZ4QcmcKg2KcuaWw=="),
	}

	aesKey, err := dhutil.GenerateSharedKey(privateKey, resp.Curve25519PublicKey)
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

	privKeyOld := os.Getenv(EnvDiffieHellmanPrivateKey)
	defer os.Setenv(EnvDiffieHellmanPrivateKey, privKeyOld)

	data, err = json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if err = ioutil.WriteFile("testdata/token-encrypted.json", data, 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove("testdata/token-encrypted.json")

	sinks := []*config.Sink{
		&config.Sink{
			Type:   "file",
			DHType: "curve25519",
			AAD:    "foobar",
			Config: map[string]interface{}{
				"path": "testdata/token-encrypted.json",
			},
		},
	}

	cases := []struct {
		name   string
		env    string
		tokens int
	}{
		{
			"valid-base64",
			base64.StdEncoding.EncodeToString(privateKey),
			1,
		},
		{
			"invalid-base64",
			"not valid base64!",
			0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv(EnvDiffieHellmanPrivateKey, tc.env)

			tokens := GetCachedTokens(hclog.NewNullLogger(), sinks, nil)
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
