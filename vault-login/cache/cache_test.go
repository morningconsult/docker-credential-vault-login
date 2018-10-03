package cache

import (
	"path/filepath"
	"fmt"
	"os"
	"testing"

	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

func TestNewCacheUtil_Enabled(t *testing.T) {
	const cacheDir = "/tmp/docker-credential-vault-login-testing"
	const expectedTTL = 12345

	os.Setenv(EnvDisableCache, "")
	os.Setenv(EnvCacheDir, cacheDir)
	os.Setenv(EnvTokenTTL, fmt.Sprintf("%d", expectedTTL))

	cacheUtilUntyped := NewCacheUtil()

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

	if cacheUtil.tokenTTL != expectedTTL {
		t.Fatalf("Expected cacheUtil.tokenTTL to be %d, but got %d instead",
			expectedTTL, cacheUtil.tokenTTL)
	}
}

func TestNewCacheUtil_Disabled(t *testing.T) {
	const cacheDir = "/tmp/docker-credential-vault-login-testing"

	os.Setenv(EnvDisableCache, "true")
	os.Setenv(EnvCacheDir, cacheDir)

	cacheUtilUntyped := NewCacheUtil()

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

	cacheUtil := NewDefaultCacheUtil()
	if cacheUtil.GetCacheDir() != cacheDir {
		t.Fatalf("Expected cacheUtil.cacheDir to be %q, but got %q instead",
			cacheDir, cacheUtil.cacheDir)
	}
}

func TestDefaultCacheUtil_RenewToken(t *testing.T) {
	const (
		roleName = "dev-test"
		cacheDir = "/tmp/docker-credential-vault-login-testing"
	)

	os.Setenv(EnvDisableCache, "")
	os.Setenv(EnvCacheDir, cacheDir)

	// Start the Vault testing cluster
	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := test.NewPreConfiguredVaultClient(t, cluster)

	// Create a token for a role
	secret, err := client.Logical().Write(filepath.Join("auth", "token", "create"), map[string]interface{}{
		"renewable": true,
		"ttl": "10m",
		"policies": []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cacheDir := NewDefaultCacheUtil()

	cases := []struct{
		renewable bool
		ttl       string
		err       bool
	}{
		{},
	}

	// When you run the test, you gotta first create the token

	// ttl, err := secret.TokenTTL()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// t.Log(ttl.String())
}