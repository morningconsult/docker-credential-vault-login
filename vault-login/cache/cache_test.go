// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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
	"net/url"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/mitchellh/mapstructure"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/logging"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

func TestSetupCacheDir_EnvCacheDir(t *testing.T) {
	os.Setenv(EnvCacheDir, "testdata")

	cacheDir := SetupCacheDir("")

	if cacheDir != "testdata" {
		t.Fatalf("expected \"testdata\", but got %q instead", cacheDir)
	}
}

func TestSetupCacheDir_BackupCache(t *testing.T) {
	// This will cause github.com/mitchellh/go-homedir.Expand() to fail
	env := awstesting.StashEnv()
	defer awstesting.PopEnv(env)

	cacheDir := SetupCacheDir("")

	if cacheDir != BackupCacheDir {
		t.Fatalf("expected %q, but got %q instead",
			BackupCacheDir, cacheDir)
	}
}

func TestSetupCacheDir_CacheDirArg(t *testing.T) {
	var cacheDirArg = "testdata"

	env := awstesting.StashEnv()
	defer awstesting.PopEnv(env)

	cacheDir := SetupCacheDir(cacheDirArg)

	if cacheDir != cacheDirArg {
		t.Fatalf("expected %q, but got %q instead",
			cacheDirArg, cacheDir)
	}
}

func TestNewCacheUtil(t *testing.T) {
	const cacheDir = "testdata"

	cases := []struct {
		name      string
		env       string
		cacheType string
		configArg bool
	}{
		{
			"enabled-a",
			"false",
			"default",
			false,
		},
		{
			"enabled-b",
			"f",
			"default",
			false,
		},
		{
			"enabled-c",
			"i am not a bool",
			"default",
			false,
		},
		{
			"enabled-d",
			"",
			"default",
			false,
		},
		{
			"disabled-a",
			"true",
			"null",
			false,
		},
		{
			"disabled-b",
			"t",
			"null",
			false,
		},
		{
			"disabled-c",
			"false",
			"null",
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv(EnvDisableCache, tc.env)
			cacheUtilUntyped := NewCacheUtil(cacheDir, tc.configArg)

			switch tc.cacheType {
			case "default":
				if _, ok := cacheUtilUntyped.(*DefaultCacheUtil); !ok {
					t.Fatalf("Expected to receive an instance of cache.DefaultCacheUtil but didn't")
				}
			case "null":
				if _, ok := cacheUtilUntyped.(*NullCacheUtil); !ok {
					t.Fatalf("Expected to receive an instance of cache.DefaultCacheUtil but didn't")
				}
			default:
				t.Fatalf("Received unknown CacheUtil type: %T", cacheUtilUntyped)
			}
		})
	}
}

func TestCacheUtil_CacheDir(t *testing.T) {
	const cacheDir = "testdata"

	os.Unsetenv(EnvDisableCache)
	os.Setenv(EnvCacheDir, cacheDir)
	cacheUtil := NewCacheUtil("", false)

	if cacheUtil.CacheDir() != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.CacheDir())
	}
}

func TestDefaultCacheUtil_CacheNewToken(t *testing.T) {
	const cacheDir = "testdata"
	const method = config.VaultAuthMethodAWSIAM
	const token = "a unique client token"
	const addr = "https://vault.service.consul"

	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil(cacheDir, false)

	cases := []struct {
		name string
		url  string
		arg  *api.Secret
		err  bool
	}{
		{
			"success",
			addr,
			&api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   token,
					Renewable:     true,
					LeaseDuration: 86400,
				},
			},
			false,
		},
		{
			"bad-vault-address",
			"@!#$&^@#$%&@$%&",
			&api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   token,
					Renewable:     true,
					LeaseDuration: 86400,
				},
			},
			true,
		},
		{
			"bad-token",
			addr,
			&api.Secret{
				Data: map[string]interface{}{
					// Token is not a string
					"id": 1234,
				},
			},
			true,
		},
		{
			"bad-ttl",
			addr,
			&api.Secret{
				Data: map[string]interface{}{
					// Token is not a string
					"ttl": "I really should be an int",
				},
			},
			true,
		},
		{
			"bad-renewable",
			addr,
			&api.Secret{
				Data: map[string]interface{}{
					// Token is not a string
					"renewable": "I should really be a boolean",
				},
			},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTestdata(cacheDir)
			err := cacheUtil.CacheNewToken(tc.arg, tc.url, method)
			defer clearTestdata(cacheDir)

			if tc.err {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error but received one: %v", err)
			}

			cachedToken := loadTokenFromFile(t, cacheUtil.TokenFile(), tc.url, method)

			// Must select the field corresponding to "method"
			if cachedToken.TokenID() == "" {
				t.Fatalf("token for method %q should not have been empty", string(method))
			}

			if cachedToken.TokenID() != token {
				t.Fatalf("expected token %q, but got %q", token, cachedToken.Token)
			}

			if cachedToken.ExpirationTS() == 0 {
				t.Fatal("expiration should not be 0")
			}
		})
	}
}

func TestDefaultCacheUtil_CacheNewToken_OverwritesEntries(t *testing.T) {
	const cacheDir = "testdata"
	const token = "a unique Vault token"
	const method = config.VaultAuthMethodAWSIAM
	const addr = "https://vault.service.consul"

	clearTestdata(cacheDir)
	defer clearTestdata(cacheDir)

	os.Setenv(EnvCacheDir, "testdata")
	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil("", false)

	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	tokenFileOriginal := map[string]interface{}{
		host: map[string]interface{}{
			string(method): map[string]interface{}{
				"token":      token,
				"expiration": 1234,
				"renewable":  true,
			},
			"other method": map[string]interface{}{
				"token":      token,
				"expiration": 5678,
				"renewable":  false,
			},
		},
	}
	writeTokenFile(t, tokenFileOriginal, cacheUtil.TokenFile())

	newSecret := &api.Secret{
		Auth: &api.SecretAuth{
			ClientToken:   "new token",
			Renewable:     true,
			LeaseDuration: 86400,
		},
	}

	if err = cacheUtil.CacheNewToken(newSecret, addr, method); err != nil {
		t.Fatal(err)
	}

	newToken := loadTokenFromFile(t, cacheUtil.TokenFile(), addr, method)
	if newToken.TokenID() != "new token" {
		t.Fatalf("should have overwritten cached token entry (host: %q, method: %q)", host, string(method))
	}
}

func TestDefaultCacheUtil_LookupToken(t *testing.T) {
	const cacheDir = "testdata"
	const token = "a unique Vault token"
	const method = config.VaultAuthMethodAWSIAM
	const addr = "https://vault.service.consul"

	os.Setenv(EnvCacheDir, "testdata")
	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil("", false)

	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	cases := []struct {
		name string
		addr string
		file map[string]interface{}
		err  bool
	}{
		{
			"success",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{
						"token":      token,
						"expiration": 1234,
						"renewable":  true,
					},
				},
			},
			false,
		},
		{
			"no-entry-for-host",
			addr,
			map[string]interface{}{
				"different.host.com": "",
			},
			false,
		},
		{
			"no-entry-for-method",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					"fake method": "",
				},
			},
			false,
		},
		{
			"malformed-host-entry",
			addr,
			map[string]interface{}{
				host: "i'm just a string :(",
			},
			true,
		},
		{
			"malformed-method-entry",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): "i'm just a string :(",
				},
			},
			true,
		},
		{
			"file-missing",
			addr,
			map[string]interface{}{},
			false,
		},
		{
			"empty-token",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{
						"token":      "",
						"expiration": 1234,
						"renewable":  true,
					},
				},
			},
			true,
		},
		{
			"no-expiration",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{
						"token":     token,
						"renewable": true,
					},
				},
			},
			true,
		},
		{
			"bad-expiration-type",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{
						"token":      token,
						"expiration": "i should be an int",
						"renewable":  true,
					},
				},
			},
			true,
		},
		{
			"bad-renewable-type",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{
						"token":      token,
						"expiration": 1234,
						"renewable":  "i should be a bool",
					},
				},
			},
			true,
		},
		{
			"empty-json",
			addr,
			map[string]interface{}{
				host: map[string]interface{}{
					string(method): map[string]interface{}{},
				},
			},
			true,
		},
		{
			"file-not-json",
			addr,
			map[string]interface{}{},
			true,
		},
		{
			"bad-address",
			"#$%&^!#$",
			map[string]interface{}{},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTestdata(cacheDir)
			defer clearTestdata(cacheDir)

			if tc.name == "file-not-json" {
				writeDataToFile(t, []byte(""), cacheUtil.TokenFile())
			} else if tc.name != "file-missing" {
				writeTokenFile(t, tc.file, cacheUtil.TokenFile())
			}

			_, err := cacheUtil.LookupToken(tc.addr, method)

			if tc.err && (err == nil) {
				t.Fatal("expected an error but didn't receive one")
			}

			if !tc.err && (err != nil) {
				t.Fatalf("expected no error but received one: %v", err)
			}
		})
	}
}

func TestDefaultCacheUtil_RenewToken(t *testing.T) {
	const cacheDir = "testdata"
	const method = config.VaultAuthMethodAWSIAM

	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil(cacheDir, false)

	// Start the Vault testing cluster
	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := test.NewPreConfiguredVaultClient(t, cluster)

	cases := []struct {
		name      string
		renewable bool
		client    *api.Client
		err       bool
	}{
		{
			"renewable",
			true,
			client,
			false,
		},
		{
			"non-renewable",
			false,
			client,
			true,
		},
		{
			"nil-client",
			false,
			nil,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTestdata(cacheDir)
			defer clearTestdata(cacheDir)

			// Create a token
			secret, err := client.Logical().Write(filepath.Join("auth", "token", "create"), map[string]interface{}{
				"renewable": tc.renewable,
				"ttl":       "1h",
				"policies":  []string{"test"},
			})
			if err != nil {
				t.Fatal(err)
			}

			token, err := secret.TokenID()
			if err != nil {
				t.Fatal(err)
			}

			err = cacheUtil.RenewToken(&CachedToken{
				Token:      token,
				Expiration: time.Now().Add(time.Hour * 1).Unix(),
				Renewable:  tc.renewable,
				method:     method,
			}, tc.client)

			if tc.err && (err == nil) {
				t.Fatal("expected an error but didn't receive one")
			}

			if !tc.err && (err != nil) {
				t.Fatalf("expected no error but received one: %v", err)
			}
		})
	}
}

func TestDefaultCacheUtil_ClearCachedToken(t *testing.T) {
	const (
		cacheDir     = "testdata"
		addr         = "https://vault.server.consul"
		erasedMethod = config.VaultAuthMethodAWSIAM
		keptMethod   = config.VaultAuthMethodAWSEC2
	)

	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil(cacheDir, false)

	tokenFileOriginal := map[string]interface{}{
		host: map[string]interface{}{
			string(erasedMethod): map[string]interface{}{
				"token":      "token",
				"expiration": time.Now().Unix(),
				"renewable":  false,
			},
			string(keptMethod): map[string]interface{}{
				"token":      "other token",
				"expiration": time.Now().Unix(),
				"renewable":  true,
			},
		},
	}

	writeTokenFile(t, tokenFileOriginal, cacheUtil.TokenFile())

	cacheUtil.ClearCachedToken(addr, erasedMethod)

	// ClearCachedToken should have deleted the entry for erasedMethod
	// but not the entry for keptMethod
	tokenFileNew := readTokenFile(t, cacheUtil.TokenFile())
	serverTokens, ok := tokenFileNew[host].(map[string]interface{})
	if !ok {
		t.Fatal("failed to read token file")
	}
	
	if _, ok = serverTokens[string(erasedMethod)]; ok {
		t.Fatalf("should have erased cached token for method %q", string(erasedMethod))
	}
	if _, ok = serverTokens[string(keptMethod)].(map[string]interface{}); !ok {
		t.Fatalf("should not have erased cached token for method %q", string(erasedMethod))
	}
}

func TestDefaultCacheUtil_ClearCachedToken_BadFile(t *testing.T) {
	const cacheDir = "testdata"

	os.Unsetenv(EnvDisableCache)

	cacheUtil := NewCacheUtil(cacheDir, false)

	cases := []struct {
		name     string
		fileData string
	}{
		{
			"non-json",
			"i am not a json",
		},
		{
			"invalid-json",
			"{{}",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTestdata(cacheDir)
			defer clearTestdata(cacheDir)

			writeDataToFile(t, []byte(tc.fileData), cacheUtil.TokenFile())

			cacheUtil.ClearCachedToken("https://vault.service.consul", config.VaultAuthMethodAWSIAM)

			// ClearCachedToken should have deleted the file
			if _, err := os.Stat(cacheUtil.TokenFile()); err == nil {
				t.Fatal("should have deleted the tokens.json file")
			}
		})
	}
}

func TestNullCacheUtil_CacheDir(t *testing.T) {
	const cacheDir = "testdata"

	os.Setenv(EnvCacheDir, cacheDir)
	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil("", false)
	if cacheUtil.CacheDir() != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.CacheDir())
	}
}

func TestNullCacheUtil_TokenFile(t *testing.T) {
	const cacheDir = "testdata"
	var expected = filepath.Join(cacheDir, "tokens.json")

	os.Setenv(EnvCacheDir, cacheDir)
	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil("", false)
	if cacheUtil.TokenFile() != expected {
		t.Fatalf("Expected cacheUtil.tokenFilename to be %q, but got %q instead",
			expected, cacheUtil.TokenFile())
	}
}

func TestNullCacheUtil_LookupToken(t *testing.T) {
	const cacheDir = "testdata"

	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil(cacheDir, false)
	token, err := cacheUtil.LookupToken("", config.VaultAuthMethodAWSIAM)
	if err != nil {
		t.Fatal("expected a nil error")
	}
	if token != nil {
		t.Fatal("expected a nil *CachedToken value")
	}
}

func TestNullCacheUtil_CacheNewToken(t *testing.T) {
	const cacheDir = "testdata"

	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil(cacheDir, false)

	err := cacheUtil.CacheNewToken(nil, "", config.VaultAuthMethodAWSIAM)
	if err != nil {
		t.Fatal("expected a nil error")
	}
}

func TestNullCacheUtil_RenewToken(t *testing.T) {
	const cacheDir = "testdata"

	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil(cacheDir, false)

	err := cacheUtil.RenewToken(nil, nil)
	if err != nil {
		t.Fatal("expected a nil error")
	}
}

func TestNullCacheUtil_ClearCachedToken(t *testing.T) {
	const cacheDir = "testdata"

	os.Setenv(EnvDisableCache, "true")

	cacheUtil := NewCacheUtil(cacheDir, false)

	// Should return nothing and have no effect at all
	cacheUtil.ClearCachedToken("", config.VaultAuthMethodAWSIAM)
}

func TestMain(m *testing.M) {
	logging.SetupTestLogger()
	status := m.Run()
	clearTestdata("testdata")
	os.Exit(status)
}

func writeTokenFile(t *testing.T, v interface{}, tokenfile string) {
	data, err := jsonutil.EncodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	writeDataToFile(t, data, tokenfile)
}

func readTokenFile(t *testing.T, tokenfile string) map[string]interface{} {
	data, err := ioutil.ReadFile(tokenfile)
	if err != nil {
		t.Fatal(err)
	}

	var tokenFile map[string]interface{}
	if err = jsonutil.DecodeJSON(data, &tokenFile); err != nil {
		t.Fatal(err)
	}
	
	return tokenFile
}

func writeDataToFile(t *testing.T, data []byte, tokenfile string) {
	if err := os.MkdirAll(filepath.Dir(tokenfile), 0700); err != nil {
		t.Fatal(err)
	}

	file, err := os.OpenFile(tokenfile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		t.Fatal(err)
	}
}

func loadTokenFromFile(t *testing.T, filename string, vaultAddr string, method config.VaultAuthMethod) *CachedToken {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var tokenFile = make(map[string]interface{})
	if err = jsonutil.DecodeJSONFromReader(file, &tokenFile); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(vaultAddr)
	if err != nil {
		t.Fatal(err)
	}

	serverTokens, ok := tokenFile[u.Host].(map[string]interface{})
	if !ok {
		t.Fatalf("no cached tokens for host %q", u.Host)
	}

	tokenMap, ok := serverTokens[string(method)].(map[string]interface{})
	if !ok {
		t.Fatalf("no cached token found (host: %q, method: %q)", u.Host, string(method))
	}

	var cachedToken = new(CachedToken)
	if err = mapstructure.Decode(tokenMap, cachedToken); err != nil {
		t.Fatal(err)
	}

	return cachedToken
}

func clearTestdata(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*token*"))
	for _, file := range files {
		os.Remove(file)
	}
}