package vault

import (
        "fmt"
        "os"
        "testing"

        uuid "github.com/hashicorp/go-uuid"
        "github.com/aws/aws-sdk-go/awstesting"
        test "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/testing"
)

func TestNewClientFactoryAWSAuth_Success(t *testing.T) {
        const role = "test-iam-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: role})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
        os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

        factory := NewClientFactoryAWSAuth(role, "")
        vaultClient, err := factory.NewClient()
        if err != nil {
                t.Fatal(err)
        }

        client, _ := vaultClient.(*DefaultClient)

        if v := client.RawClient().Token(); v == "" {
                t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
        }
}

// TestNewClientFactoryAWS_UnconfiguredRole checks that when
// ClientFactoryAWSAuth.NewClient() is called for a Vault role that
// has not been configured to login using the AWS IAM credentials
// on the host machine, an error is returned.
func TestNewClientFactoryAWSAuth_UnconfiguredRole(t *testing.T) {
        const badrole = "the-fake-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: "the-real-role"})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
        os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

        factory := NewClientFactoryAWSAuth(badrole, "")
        _, err := factory.NewClient()
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
        }

}

// TestNewClientFactoryAWSAuth_BadVaultAddr tests that the
// incorrect VAULT_ADDR value is set, ClientFactoryAWSAuth.NewClient()
// returns an error.
func TestNewClientFactoryAWS_BadVaultAddr(t *testing.T) {
        const role = "test-iam-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: role})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
        // Incorrect Vault test server URL
        os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")

        factory := NewClientFactoryAWSAuth(role, "")
        _, err := factory.NewClient()
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
        }
}
// TestNewClientFactoryTokenAuth_Success tests that when
// ClientFactoryTokenAuth.NewClient() is called and the 
// VAULT_TOKEN environment variable is set with a vault
// token, no error is returned.
func TestNewClientFactoryTokenAuth_Success(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        token, err := uuid.GenerateUUID()
        if err != nil {
                t.Fatal(err)
        }
        os.Setenv("VAULT_TOKEN", token)

        factory := NewClientFactoryTokenAuth()
        _, err = factory.NewClient()
        if err != nil {
                t.Fatal(err)
        }
}

func TestNewClientFactoryTokenAuth_NoToken(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        os.Unsetenv("VAULT_TOKEN")

        factory := NewClientFactoryTokenAuth()
        _, err := factory.NewClient()
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
        }
}