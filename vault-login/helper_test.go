package helper

import (
	"fmt"
        "net/http"
        "path/filepath"
        "os"
	"testing"

        "github.com/aws/aws-sdk-go/awstesting"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
        "github.com/hashicorp/vault/vault"
        
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/config"
)

const (
        EnvAWSAccessKeyID string = "AWS_ACCESS_KEY_ID"

        EnvAWSAccessKey string = "AWS_ACCESS_KEY"

        EnvAWSSecretAccessKey string = "AWS_SECRET_ACCESS_KEY"

        EnvAWSSecretKey string = "AWS_SECRET_KEY"

        TestAccessKey string = "AKIAIJWPJLKME2OBDB6Q"

        TestSecretKey string = "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"
)

var testGoodConfigFile string = filepath.Abs(filepath.Join("testdata", "config_good.json"))

func TestHelperGetsCreds(t *testing.T) {
	var (
		secretPath = "secret/foo/bar"
		secret     = map[string]interface{}{
			"username": "docker@user.com",
			"password": "potato",
		}
	)

        cluster := startTestCluster(t)
	defer cluster.Cleanup()
        
        client := newClient(t, cluster)

	_, err := client.Logical().Write(secretPath, secret)
	if err != nil {
		t.Fatal(err)
        }
        
        os.Setenv(config.EnvConfigFilePath, testGoodConfigFile)
        setTestEnvVars()

	helper := NewHelper()
	user, pw, err := helper.Get("")
	if err != nil {
		t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
	}
	if v, _ := secret["username"].(string); v != user {
		t.Errorf("Expected username %q, got %q", v, user)
	}
	if v, _ := secret["password"].(string); v != pw {
		t.Errorf("Expected password %q, got %q", v, pw)
	}
}

// func TestHelperFailsWhenNoSecret(t *testing.T) {
//         cluster := startTestCluster(t)
//         defer cluster.Cleanup()

//         client := newClient(t, cluster)

//         helper := NewHelper("secret/foo/bar", client)
//         user, pw, err := helper.Get("")
//         if err == nil {
//                 t.Fatal("expected an error when no secret is found but got no error")
//         }
//         if user != "" {
//                 t.Fatal("returned username should be an empty string when secret does not exist")
//         }
//         if pw != "" {
//                 t.Fatal("returned password should be an empty string when secret does not exist")
//         }
// }

// func TestHelperFailsWhenNoCreds(t *testing.T) {
//         var (
//                 secretPath = "secret/foo/bar"
//                 secret     = map[string]interface{}{
//                         "foo": "bar",
//                         "bim": "baz",
//                 }
//         )

//         cluster := startTestCluster(t)
//         defer cluster.Cleanup()

//         client := newClient(t, cluster)

//         _, err := client.Logical().Write(secretPath, secret)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

//         helper := NewHelper(secretPath, client)
//         user, pw, err := helper.Get("")
//         if err == nil {
//                 t.Fatal("expected an error when no credentials are found but got no error")
//         }
//         if user != "" {
//                 t.Fatal("returned username should be an empty string when no credentials found")
//         }
//         if pw != "" {
//                 t.Fatal("returned password should be an empty string when no credentials found")
//         }
// }

func TestMain(m *testing.M) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        os.Exit(m.Run())
}

func startTestCluster(t *testing.T) *vault.TestCluster {
        base := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(log.Error),
	}

	cluster := vault.NewTestCluster(t, base, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
        cluster.Start()
        return cluster
}

func newClient(t *testing.T, cluster *vault.TestCluster) *api.Client {
        cores := cluster.Cores

	core := cores[0].Core
	vault.TestWaitActive(t, core)

	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("https://127.0.0.1:%d", cores[0].Listeners[0].Address.Port)
	config.HttpClient.Transport.(*http.Transport).TLSClientConfig = cores[0].TLSConfig

	client, err := api.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
        client.SetToken(cluster.RootToken)
        return client
}

func clearEnvVars() {
        os.Unsetenv(EnvAWSAccessKeyID)
        os.Unsetenv(EnvAWSAccessKey)
        os.Unsetenv(EnvAWSSecretAccessKey)
        os.Unsetenv(EnvAWSSecretKey)
}

func setTestEnvVars() {
        clearEnvVars()
        os.Setenv(EnvAWSAccessKey, TestAccessKey)
        os.Setenv(EnvAWSSecretKey, TestSecretKey)
}