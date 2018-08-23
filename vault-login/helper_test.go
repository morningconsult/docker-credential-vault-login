package helper

import (
        "encoding/json"
        "fmt"
        "io/ioutil"
        "net/http"
        "path/filepath"
        "os"
        "testing"

        "github.com/aws/aws-sdk-go/awstesting"
        "github.com/cihub/seelog"
        log "github.com/hashicorp/go-hclog"

        "github.com/phayes/freeport"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
        "github.com/hashicorp/vault/vault"
        vaulthttp "github.com/hashicorp/vault/http"

        logger "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/logging"
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

var (
        testAwsConfigFile string = filepath.Join("testdata", "config_aws.json")
        testTokenConfigFile string = filepath.Join("testdata", "config_token.json")
)

func TestHelperGet_AWS_Success(t *testing.T) {
        port, err := freeport.GetFreePort()
        if err != nil {
                t.Fatal(err)
        }

	var (
                testConfigFile = testAwsConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &testVaultServerOptions{
                        port:       port,
                        secretPath: cfg.Secret,
                        secret:     map[string]interface{}{
                                "username": "frodo.baggins@shire.com",
                                "password": "potato",
                        },
                        role:       cfg.Role,
                }
        )

        server := makeMockVaultServer(t, opts)
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)

        // Set AWS credential environment variables
        setTestAWSEnvVars()

        // Set the environment variable informing the program where
        // the config.json file is located
        os.Setenv(config.EnvConfigFilePath, testConfigFile)

        os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1:%d", opts.port))
        
	helper := NewHelper(nil)
	user, pw, err := helper.Get("")
	if err != nil {
		t.Fatalf("error retrieving Docker credentials from Vault: %v", err)
	}
	if v, _ := opts.secret["username"].(string); v != user {
		t.Errorf("Expected username %q, got %q", v, user)
	}
	if v, _ := opts.secret["password"].(string); v != pw {
		t.Errorf("Expected password %q, got %q", v, pw)
	}
}

// TestHelperGet_BadPath tests that when a user does not provide 
// the path to their Docker credentials in the "vault_secret_path"
// field of the config.json file, the helper.Get() method returns
// an error
func TestHelperGet_AWS_BadPath(t *testing.T) {
        port, err := freeport.GetFreePort()
        if err != nil {
                t.Fatal(err)
        }

	var (
                testConfigFile = testAwsConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &testVaultServerOptions{
                        port: port,
                        // secretPath delibarately does not match the "vault_secret_path" field
                        // of the config.json file in order to cause an error -- this is the
                        // purpose of this unit test
                        secretPath: "secret/bim/baz",
                        secret: map[string]interface{}{
                                "username": "frodo.baggins@shire.com",
                                "password": "potato",
                        },
                        role: cfg.Role,
                }
        )

        server := makeMockVaultServer(t, opts)
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)

        // Set AWS credential environment variables
        setTestAWSEnvVars()

        // Set the environment variable informing the program where
        // the config.json file is located
        os.Setenv(config.EnvConfigFilePath, testConfigFile)

        os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1:%d", opts.port))
        
	helper := NewHelper(nil)
	_, _, err = helper.Get("")
	if err == nil {
                t.Errorf("should have returned and error, but didn't.")
        }
}

// TestHelperGet_NoSecret tests that when a user provides the path
// to their Docker credentials in the "vault_secret_path" field of
// the config.json file but no credentials are present at that location,
// the helper.Get() method returns an error.
func TestHelperGet_AWS_NoSecret(t *testing.T) {
        port, err := freeport.GetFreePort()
        if err != nil {
                t.Fatal(err)
        }

	var (
                testConfigFile = testAwsConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &testVaultServerOptions{
                        port: port,
                        secretPath: cfg.Secret,
                        // secret is initialized with no data so that when the helper
                        // attempts to read the secret at secretPath, it will get 
                        // no data, and then return an error
                        secret: map[string]interface{}{},
                        role: cfg.Role,
                }
        )

        server := makeMockVaultServer(t, opts)
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)

        // Set AWS credential environment variables
        setTestAWSEnvVars()

        // Set the environment variable informing the program where
        // the config.json file is located
        os.Setenv(config.EnvConfigFilePath, testConfigFile)

        os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1:%d", opts.port))
        
	helper := NewHelper(nil)
	_, _, err = helper.Get("")
	if err == nil {
                t.Errorf("should have returned and error, but didn't.")
        }
}

// TestHelperGet_BadRole tests that when a user provides a Vault role
// in the "vault_role" field of the config.json file that has not been
// configured with a policy permitting that role to read the secret,
// the helper.Get() method returns an error.
func TestHelperGet_AWS_BadRole(t *testing.T) {
        port, err := freeport.GetFreePort()
        if err != nil {
                t.Fatal(err)
        }

	var (
                testConfigFile = testAwsConfigFile
		cfg            = readConfig(t, testConfigFile)
		opts           = &testVaultServerOptions{
                        port: port,
                        secretPath: cfg.Secret,
                        secret: map[string]interface{}{},
                        role: "fake-role",
                }
        )

        server := makeMockVaultServer(t, opts)
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)

        // Set AWS credential environment variables
        setTestAWSEnvVars()

        // Set the environment variable informing the program where
        // the config.json file is located
        os.Setenv(config.EnvConfigFilePath, testConfigFile)

        os.Setenv(api.EnvVaultAddress, fmt.Sprintf("http://127.0.0.1:%d", opts.port))
        
	helper := NewHelper(nil)
	_, _, err = helper.Get("")
	if err == nil {
                t.Errorf("should have returned and error, but didn't.")
        }
}

func TestHelperGet_Token_Success(t *testing.T) {
        var (
                testConfigFile = testTokenConfigFile
                cfg            = readConfig(t, testConfigFile)
                secret         = map[string]interface{}{
                        "username": "frodo.baggins@theshire.com",
                        "password": "potato",
                }
        )

        cluster := startTestCluster(t)
        defer cluster.Cleanup()

        client := newClient(t, cluster)

        writeSecret(t, client, cfg.Secret, secret)

        // Set the environment variable informing the program where
        // the config.json file is located
        os.Setenv(config.EnvConfigFilePath, testConfigFile)

        // Set VAULT_TOKEN environment variable to the token already
        // assigned to the client (to conform with ClientFactory behavior)
        os.Setenv(api.EnvVaultToken, client.Token())

        helper := NewHelper(client)
        user, pw, err := helper.Get("")
        if err != nil {
                t.Fatal(err)
        }
        if username, ok := secret["username"].(string); !ok || username != user {
                t.Fatalf("Wrong username (got %q, expected %q)", user, username)
        }
        if password, ok := secret["password"].(string); !ok || password != pw {
                t.Fatalf("Wrong password (got %q, expected %q)", pw, password)
        }
}

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
        defer seelog.Flush()
        logger.SetupTestLogger()
        os.Exit(m.Run())
}

func startTestCluster(t *testing.T) *vault.TestCluster {
        base := &vault.CoreConfig{
                Logger: logging.NewVaultLogger(log.Error),
                // CredentialBackends: map[string]logical.Factory{
                //         "aws": credAws.Factory,
                // },
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

func setTestAWSEnvVars() {
        os.Setenv(EnvAWSAccessKey, TestAccessKey)
        os.Setenv(EnvAWSSecretKey, TestSecretKey)
}

func writeSecret(t *testing.T, client *api.Client, secretPath string, secret map[string]interface{}) {
	if _, err := client.Logical().Write(secretPath, secret); err != nil {
		t.Fatal(err)
        }
}

func readConfig(t *testing.T, testConfigFile string) *config.CredHelperConfig {
        data, err := ioutil.ReadFile(testConfigFile)
        if err != nil {
                t.Fatal(err)
        }

        var cfg = new(config.CredHelperConfig)
        if err = json.Unmarshal(data, cfg); err != nil {
                t.Fatal(err)
        }
        return cfg
}
