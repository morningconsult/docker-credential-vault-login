package cache

import (
	"path/filepath"
	"os"
	"testing"
	"time"

	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

func TestNewCacheUtil_Enabled(t *testing.T) {
	const cacheDir = "/tmp/docker-credential-vault-login-testing"
	const expectedTTL = 12345

	os.Setenv(EnvDisableCache, "")
	os.Setenv(EnvCacheDir, cacheDir)

	cacheUtilUntyped := NewCacheUtil(nil)

	cacheUtil, ok := cacheUtilUntyped.(*DefaultCacheUtil)
	if !ok {
		t.Fatalf("Expected to receive an instance of cache.DefaultCacheUtil, but didn't")
	}

	if cacheUtil.cacheDir != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.cacheDir)
	}

	var expectedTokenCacheDir = filepath.Join(cacheDir, "tokens")
	if cacheUtil.tokenCacheDir != expectedTokenCacheDir {
		t.Fatalf("Expected cacheUtil.tokenCacheDir to be %q, but got %q instead",
			expectedTokenCacheDir, cacheUtil.tokenCacheDir)
	}
}

func TestNewCacheUtil_Disabled(t *testing.T) {
	const cacheDir = "/tmp/docker-credential-vault-login-testing"

	os.Setenv(EnvDisableCache, "true")
	os.Setenv(EnvCacheDir, cacheDir)

	cacheUtilUntyped := NewCacheUtil(nil)

	cacheUtil, ok := cacheUtilUntyped.(*NullCacheUtil)
	
	if !ok {
		t.Fatalf("Expected to receive an instance of cache.DefaultCacheUtil, but didn't")
	}

	if cacheUtil.cacheDir != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.cacheDir)
	}
}

func TestDefaultCacheUtil_GetCacheDir(t *testing.T) {
	const cacheDir = "/tmp/docker-credential-vault-login-testing"

	os.Setenv(EnvDisableCache, "")
	os.Setenv(EnvCacheDir, cacheDir)

	cacheUtil := NewDefaultCacheUtil(nil)
	if cacheUtil.GetCacheDir() != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.cacheDir)
	}
}

func TestDefaultCacheUtil_RenewToken(t *testing.T) {
	const roleName = "dev-test"

	os.Setenv(EnvDisableCache, "")
	os.Setenv(EnvCacheDir, "testdata")

	// Start the Vault testing cluster
	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := test.NewPreConfiguredVaultClient(t, cluster)
	rootToken := client.Token()

	cacheDir := NewDefaultCacheUtil(client)

	cases := []struct{
		name      string
		renewable bool
		ttl       string
		err       bool
	}{
		{
			"renewable",
			true,
			"1h",
			false,
		},
		{
			"non-renewable",
			false,
			"1h",
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client.SetToken(rootToken)
			// Create a token
			secret, err := client.Logical().Write(filepath.Join("auth", "token", "create"), map[string]interface{}{
				"renewable": tc.renewable,
				"ttl":       tc.ttl,
				"policies":  []string{"test"},
			})
			if err != nil {
				t.Fatal(err)
			}

			token, err := secret.TokenID()
			if err != nil {
				t.Fatal(err)
			}

			err = cacheDir.RenewToken(&CachedToken{
				Token:      token,
				Expiration: time.Now().Add(time.Hour * 1).Unix(),
				Renewable:  tc.renewable,
				AuthMethod: config.VaultAuthMethodAWSIAM,
			})

			if tc.err && err == nil {
				t.Fatal("expected an error but didn't receive one")
			}

			if !tc.err && err != nil {
				t.Fatalf("expected no error but received one: %v", err)
			}
		})
	}
}