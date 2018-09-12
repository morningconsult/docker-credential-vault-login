package vault

import (
        "fmt"
        "os"
        "testing"

	"github.com/hashicorp/vault/api"
        uuid "github.com/hashicorp/go-uuid"
        "github.com/aws/aws-sdk-go/awstesting"
        test "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/testing"
)

func TestNewClientFactoryAWSAuth_NewClient_Success(t *testing.T) {
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

// TestNewClientFactoryAWSAuth_NewClient_UnconfiguredRole checks that when
// ClientFactoryAWSAuth.NewClient() is called for a Vault role that
// has not been configured to login using the AWS IAM credentials
// on the host machine, an error is returned.
func TestNewClientFactoryAWSAuth_NewClient_UnconfiguredRole(t *testing.T) {
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

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1" + server.Addr + "/v1/auth/aws/login\nCode: 400. Raw Message:\n\n\n")
}

// TestNewClientFactoryAWSAuth_NewClient_BadVaultAddr tests that the
// incorrect VAULT_ADDR value is set, ClientFactoryAWSAuth.NewClient()
// returns an error.
func TestNewClientFactoryAWSAuth_NewClient_BadVaultAddr(t *testing.T) {
        const role = "test-iam-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: role})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
        // Incorrect Vault test server URL
        os.Setenv("VAULT_ADDR", "http://127.0.0.1:12345")

        factory := NewClientFactoryAWSAuth(role, "")
        _, err := factory.NewClient()
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
	}
	
	test.ErrorsEqual(t, err.Error(), "Put http://127.0.0.1:12345/v1/auth/aws/login: dial tcp 127.0.0.1:12345: connect: connection refused")
}

func TestNewClientFactoryAWSAuth_WithClient_Success(t *testing.T) {
        const role = "test-iam-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: role})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

        factory := NewClientFactoryAWSAuth(role, "")
        clientWithToken, err := factory.WithClient(clientNoToken)
        if err != nil {
                t.Fatal(err)
        }

        client, _ := clientWithToken.(*DefaultClient)

        if v := client.RawClient().Token(); v == "" {
                t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
        }
}

// TestNewClientFactoryAWSAuth_WithClient_BadVaultAddr tests that the
// incorrect VAULT_ADDR value is set, ClientFactoryAWSAuth.WithClient()
// returns an error.
func TestNewClientFactoryAWSAuth_WithClient_BadAddr(t *testing.T) {
        const role = "test-iam-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: role})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
	test.SetTestAWSEnvVars()
	// Incorrect Vault address
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:12345")

	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

        factory := NewClientFactoryAWSAuth(role, "")
        _, err = factory.WithClient(clientNoToken)
        if err == nil {
                t.Error("Expected to receive an error but didn't")
	}
	
	test.ErrorsEqual(t, err.Error(), "Put http://127.0.0.1:12345/v1/auth/aws/login: dial tcp 127.0.0.1:12345: connect: connection refused")
}

// TestNewClientFactoryAWSAuth_WithClient_UnconfiguredRole checks that when
// ClientFactoryAWSAuth.WithClient() is called for a Vault role that
// has not been configured to login using the AWS IAM credentials
// on the host machine, an error is returned.
func TestNewClientFactoryAWSAuth_WithClient_UnconfiguredRole(t *testing.T) {
        const badrole = "the-fake-role"

        server := test.MakeMockVaultServer(t, &test.TestVaultServerOptions{Role: "the-real-role"})
        go server.ListenAndServe()
        defer server.Close()

        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        test.SetTestAWSEnvVars()
        os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := NewClientFactoryAWSAuth(badrole, "")
	
	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

        _, err = factory.WithClient(clientNoToken)
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1" + server.Addr + "/v1/auth/aws/login\nCode: 400. Raw Message:\n\n\n")
}

func TestNewClientFactoryTokenAuth_NewClient_Success(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        token, err := uuid.GenerateUUID()
        if err != nil {
                t.Fatal(err)
        }
        os.Setenv("VAULT_TOKEN", token)

        factory := NewClientFactoryTokenAuth()
        client, err := factory.NewClient()
        if err != nil {
                t.Fatal(err)
	}
	
	c, _ := client.(*DefaultClient)

        if v := c.RawClient().Token(); v == "" {
                t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
        }
}

// TestNewClientFactoryTokenAuth_NewClient_NoToken tests that when
// ClientFactoryTokenAuth.NewClient() is called but the
// VAULT_TOKEN environment variable is not set with a Vault
// token, an error is returned.
func TestNewClientFactoryTokenAuth_NewClient_NoToken(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        os.Unsetenv("VAULT_TOKEN")

        factory := NewClientFactoryTokenAuth()
        _, err := factory.NewClient()
        if err == nil {
                t.Fatal("Expected to receive an error but didn't")
	}
	
	test.ErrorsEqual(t, err.Error(), "Vault API client has no token. Make sure to set the token using the VAULT_TOKEN environment variable")
}

func TestNewClientFactoryTokenAuth_WithClient_Success(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
        token, err := uuid.GenerateUUID()
        if err != nil {
                t.Fatal(err)
        }
        os.Setenv("VAULT_TOKEN", token)

	factory := NewClientFactoryTokenAuth()

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

        defaultClient, err := factory.WithClient(client)
        if err != nil {
                t.Fatal(err)
	}
	
	c, _ := defaultClient.(*DefaultClient)

        if v := c.RawClient().Token(); v == "" {
                t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
        }
}
// TestNewClientFactoryTokenAuth_WithClient_NoToken test that when
// ClientFactoryTokenAuth.WithClient() is called but the VAULT_TOKEN
// environment variable is not set, an error is returned.
func TestNewClientFactoryTokenAuth_WithClient_NoToken(t *testing.T) {
        oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
	os.Unsetenv("VAULT_TOKEN")

	factory := NewClientFactoryTokenAuth()

	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

        _, err = factory.WithClient(client)
        if err == nil {
                t.Error("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "VAULT_TOKEN environment variable is not set")
}

// TestNewClientFactoryTokenAuth_NewClient_BadURL tests that when
// ClientFactoryTokenAuth.NewClient() is called but the VAULT_ADDR
// value is a URL that cannot be parsed, an error is returned.
func TestNewClientFactoryTokenAuth_NewClient_BadURL(t *testing.T) {
	const badURL = "$%&%$^(*@%$^("

	oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
	os.Setenv("VAULT_ADDR", badURL)

	factory := NewClientFactoryTokenAuth()

	_, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}
	
	test.ErrorsEqual(t, err.Error(), fmt.Sprintf("parse %s: invalid URL escape \"%%&%%\"", badURL))
}

// TestNewClientFactoryAWSAuth_NewClient_BadURL tests that when
// ClientFactoryAWSAuth.NewClient() is called but the VAULT_ADDR
// value is a URL that cannot be parsed, an error is returned.
func TestNewClientFactoryAWSAuth_NewClient_BadURL(t *testing.T) {
	const badURL = "$%&%$^(*@%$^("

	oldEnv := awstesting.StashEnv()
        defer awstesting.PopEnv(oldEnv)
	os.Setenv("VAULT_ADDR", badURL)

	factory := NewClientFactoryAWSAuth("test-role", "")

	_, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), fmt.Sprintf("parse %s: invalid URL escape \"%%&%%\"", badURL))
}
