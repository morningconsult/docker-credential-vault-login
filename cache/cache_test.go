package cache

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/vault"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/dhutil"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/builtin/credential/approle"
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

	data, err := jsonutil.EncodeJSON(secret.WrapInfo)
	if err != nil {
		t.Fatal(err)
	}

	if err = ioutil.WriteFile("testdata/token-wrapped.json", data, 0644); err != nil {
		t.Fatal(err)
	}

	sinks := []*config.Sink{
		&config.Sink{
			WrapTTL: wrapTTL,
			Config:  map[string]interface{}{
				"path": "testdata/token-wrapped.json",
			},
		},
	}
	defer os.Remove("testdata/token-wrapped.json")

	tokens := GetCachedTokens(logger, sinks, client)
	if len(tokens) != 1 {
		t.Fatalf("Expected just 1 token, got %d tokens", len(tokens))
	}
	
	if tokens[0] == "" {
		t.Fatal("Token should not be empty")
	}
}

func TestGetCachedTokens_Plain(t *testing.T) {
	sinks := []*config.Sink{
		&config.Sink{
			Config: map[string]interface{}{
				"path": "testdata/token-plain.txt",
			},
		},
	}
	tokens := GetCachedTokens(hclog.NewNullLogger(), sinks, nil)
	if len(tokens) != 1 {
		t.Fatalf("Expected just 1 token, got %d tokens", len(tokens))
	}
	expected, err := ioutil.ReadFile("testdata/token-plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	if tokens[0] != string(expected) {
		t.Fatalf("Tokens differ:\n%v", cmp.Diff(tokens[0], expected))
	}
}

func TestGetCachedTokens_Encrypted(t *testing.T) {
	privateKeyData, err := ioutil.ReadFile("testdata/dh-private-key.json")
	if err != nil {
		t.Fatal(err)
	}
	privateKeyInfo := new(PrivateKeyInfo)
	if err = jsonutil.DecodeJSON(privateKeyData, privateKeyInfo); err != nil {
		t.Fatal(err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(privateKeyInfo.Curve25519PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	data, err := ioutil.ReadFile("testdata/token-encrypted.json")
	if err != nil {
		t.Fatal(err)
	}

	resp := new(dhutil.Envelope)
	if err = jsonutil.DecodeJSON(data, resp); err != nil {
		t.Fatal(err)
	}

	aesKey, err := dhutil.GenerateSharedKey(privateKey, resp.Curve25519PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(aesKey) == 0 {
		t.Fatal("derived AES key is empty")
	}

	token, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte("foobar"))
	if err != nil {
		t.Fatal(err)
	}

	sinks := []*config.Sink {
		&config.Sink{
			DHType: "curve25519",
			AAD:    "foobar",
			Config: map[string]interface{}{
				"path":    "testdata/token-encrypted.json",
				"dh_priv": "testdata/dh-private-key.json",
			},
		},
	}

	tokens := GetCachedTokens(hclog.NewNullLogger(), sinks, nil)
	if len(tokens) != 1 {
		t.Fatalf("Expected just 1 token, got %d tokens", len(tokens))
	}

	if tokens[0] != string(token) {
		t.Fatalf("Tokens differ:\n%v", cmp.Diff(tokens[0], string(token)))
	}
}
