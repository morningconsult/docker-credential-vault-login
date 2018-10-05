package vault

import (
	"fmt"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/golang/mock/gomock"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/aws/mocks"
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
)

func TestNewClientFactoryAWSIAMAuth_NewClient_Success(t *testing.T) {
	const role = "test-iam-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: role})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))
	token := os.Getenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_TOKEN")
	defer os.Setenv("VAULT_TOKEN", token)

	factory, err := NewClientFactoryAWSIAMAuth(role, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	vaultClient, _, err := factory.NewClient()
	if err != nil {
		t.Fatal(err)
	}

	client, _ := vaultClient.(*DefaultClient)

	if v := client.RawClient().Token(); v == "" {
		t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
	}
}

// TestNewClientFactoryAWSIAMAuth_NewClient_UnconfiguredRole checks that when
// ClientFactoryAWSIAMAuth.NewClient() is called for a Vault role that
// has not been configured to login using the AWS IAM credentials
// on the host machine, an error is returned.
func TestNewClientFactoryAWSIAMAuth_NewClient_UnconfiguredRole(t *testing.T) {
	const badrole = "the-fake-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: "the-real-role"})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory, err := NewClientFactoryAWSIAMAuth(badrole, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* entry for role \""+badrole+"\" not found\n")
}

// TestNewClientFactoryAWSIAMAuth_NewClient_BadVaultAddr tests that the
// incorrect VAULT_ADDR value is set, ClientFactoryAWSIAMAuth.NewClient()
// returns an error.
func TestNewClientFactoryAWSIAMAuth_NewClient_BadVaultAddr(t *testing.T) {
	const role = "test-iam-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: role})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	// Incorrect Vault test server URL
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:12345")

	factory, err := NewClientFactoryAWSIAMAuth(role, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Put http://127.0.0.1:12345/v1/auth/aws/login: dial tcp 127.0.0.1:12345: connect: connection refused")
}

func TestNewClientFactoryAWSIAMAuth_WithClient_Success(t *testing.T) {
	const role = "test-iam-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: role})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientNoToken.SetToken("")

	factory, err := NewClientFactoryAWSIAMAuth(role, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	clientWithToken, _, err := factory.WithClient(clientNoToken)
	if err != nil {
		t.Fatal(err)
	}

	client, _ := clientWithToken.(*DefaultClient)

	if v := client.RawClient().Token(); v == "" {
		t.Errorf("factory.NewClient() should have obtained a Vault token, but it didn't")
	}
}

// TestNewClientFactoryAWSIAMAuth_WithClient_BadVaultAddr tests that the
// incorrect VAULT_ADDR value is set, ClientFactoryAWSIAMAuth.WithClient()
// returns an error.
func TestNewClientFactoryAWSIAMAuth_WithClient_BadAddr(t *testing.T) {
	const role = "test-iam-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: role})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	// Incorrect Vault address
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:12345")

	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	factory, err := NewClientFactoryAWSIAMAuth(role, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(clientNoToken)
	if err == nil {
		t.Error("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Put http://127.0.0.1:12345/v1/auth/aws/login: dial tcp 127.0.0.1:12345: connect: connection refused")
}

// TestNewClientFactoryAWSIAMAuth_WithClient_UnconfiguredRole checks that when
// ClientFactoryAWSIAMAuth.WithClient() is called for a Vault role that
// has not been configured to login using the AWS IAM credentials
// on the host machine, an error is returned.
func TestNewClientFactoryAWSIAMAuth_WithClient_UnconfiguredRole(t *testing.T) {
	const badrole = "the-fake-role"

	server, _ := test.MakeMockVaultServerIAMAuth(t, &test.TestVaultServerOptions{Role: "the-real-role"})
	go server.ListenAndServe()
	defer server.Close()

	test.SetTestAWSEnvVars()
	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory, err := NewClientFactoryAWSIAMAuth(badrole, "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	clientNoToken, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(clientNoToken)
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* entry for role \""+badrole+"\" not found\n")
}

func TestNewClientFactoryTokenAuth_NewClient_Success(t *testing.T) {
	token, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("VAULT_TOKEN", token)

	factory := NewClientFactoryTokenAuth()
	client, _, err := factory.NewClient()
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
	os.Unsetenv("VAULT_TOKEN")

	factory := NewClientFactoryTokenAuth()
	_, _, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Vault API client has no token. Make sure to set the token using the VAULT_TOKEN environment variable")
}

func TestNewClientFactoryTokenAuth_WithClient_Success(t *testing.T) {
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

	defaultClient, _, err := factory.WithClient(client)
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
	os.Unsetenv("VAULT_TOKEN")

	factory := NewClientFactoryTokenAuth()
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(client)
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

	os.Setenv("VAULT_ADDR", badURL)

	factory := NewClientFactoryTokenAuth()
	_, _, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), fmt.Sprintf("parse %s: invalid URL escape \"%%&%%\"", badURL))
}

// TestNewClientFactoryAWSIAMAuth_NewClient_BadURL tests that when
// ClientFactoryAWSIAMAuth.NewClient() is called but the VAULT_ADDR
// value is a URL that cannot be parsed, an error is returned.
func TestNewClientFactoryAWSIAMAuth_NewClient_BadURL(t *testing.T) {
	const badURL = "$%&%$^(*@%$^("

	os.Setenv("VAULT_ADDR", badURL)

	factory, err := NewClientFactoryAWSIAMAuth("test-role", "", "aws")
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), fmt.Sprintf("parse %s: invalid URL escape \"%%&%%\"", badURL))
}

func TestClientFactoryAWSEC2Auth_NewClient_Success(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return(pkcs7, nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))
	token := os.Getenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_TOKEN")
	defer os.Setenv("VAULT_TOKEN", token)

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	_, _, err := factory.NewClient()
	if err != nil {
		t.Fatal(err)
	}
}

// TestClientFactoryAWSEC2Auth_NewClient_UnconfiguredRole tests that
// if the Vault role is not configured to login via the AWS EC2
// endpoint then the appropriate error is returned
func TestClientFactoryAWSEC2Auth_NewClient_UnconfiguredRole(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const (
		role    = "dev-role-ec2"
		badrole = "wrong-role"
	)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return(pkcs7, nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      badrole,
		mountPath: "aws",
	}

	_, _, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* entry for role \""+badrole+"\" not found\n")
}

// TestClientFactoryAWSEC2Auth_NewClient_BadPKCS7 tests that if
// the PKCS7 signature returned by aws.Client.GetPKCS7Signature()
// does not match the AMI ID bound to the role then then the
// appropriate error is returned.
func TestClientFactoryAWSEC2Auth_NewClient_BadPKCS7(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return("i am not the configured pkcs7 signature!", nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	_, _, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* client nonce mismatch\n")
}

// TestClientFactoryAWSEC2Auth_NewClient_NonEC2 simulates
// a situation when the EC2 authentication method is used
// on a on a non-EC2 instance. This test checks that in such
// a situation, the appropriate error is returned.
func TestClientFactoryAWSEC2Auth_NewClient_NotEC2(t *testing.T) {
	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)

	pkcs7Error := fmt.Errorf("%s\n%s %s", "RequestError: send request failed",
		"caused by: Get http://169.254.169.254/latest/dynamic/instance-identity/pkcs7:",
		"dial tcp 169.254.169.254:80: connect: no route to host")
	awsClient.EXPECT().GetPKCS7Signature().Return("", pkcs7Error)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: "hello darkness my old friend",
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	_, _, err := factory.NewClient()
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), pkcs7Error.Error())
}

func TestClientFactoryAWSEC2Auth_WithClient_Success(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return(pkcs7, nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	vaultClient, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(vaultClient)
	if err != nil {
		t.Fatal(err)
	}
}

// TestClientFactoryAWSEC2Auth_WithClient_UnconfiguredRole tests that
// if the Vault role is not configured to login via the AWS EC2
// endpoint then the appropriate error is returned
func TestClientFactoryAWSEC2Auth_WithClient_UnconfiguredRole(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const (
		role    = "dev-role-ec2"
		badrole = "wrong-role"
	)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return(pkcs7, nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      badrole,
		mountPath: "aws",
	}

	vaultClient, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(vaultClient)
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* entry for role \""+badrole+"\" not found\n")
}

// // TestClientFactoryAWSEC2Auth_WithClient_BadPKCS7 tests that if
// // the PKCS7 signature returned by aws.Client.GetPKCS7Signature()
// // does not match the AMI ID bound to the role then then the
// // appropriate error is returned.
func TestClientFactoryAWSEC2Auth_WithClient_BadPKCS7(t *testing.T) {
	const pkcs7 = `MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggHdewog
ICJwcml2YXRlSXAiIDogIjE3Mi4zMS4xNi4xNzQiLAogICJtYXJrZXRwbGFjZVByb2R1Y3RDb2Rl
cyIgOiBudWxsLAogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAidmVyc2lvbiIgOiAi
MjAxNy0wOS0zMCIsCiAgInJlZ2lvbiIgOiAidXMtZWFzdC0xIiwKICAiYWNjb3VudElkIiA6ICIx
OTQyNjA1OTQyMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTA0ZDc0ZmEyNzZlNzViMTgzIiwKICAi
YmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImtlcm5lbElkIiA6IG51bGwsCiAgInJhbWRpc2tJ
ZCIgOiBudWxsLAogICJpbnN0YW5jZVR5cGUiIDogInQyLm1pY3JvIiwKICAiYXZhaWxhYmlsaXR5
Wm9uZSIgOiAidXMtZWFzdC0xYSIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAiaW1h
Z2VJZCIgOiAiYW1pLTA0MTY5NjU2ZmVhNzg2Nzc2IiwKICAicGVuZGluZ1RpbWUiIDogIjIwMTgt
MDktMTNUMTY6Mjc6MjFaIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcG
A1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1hem9u
IFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsG
CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwOTEzMTYyNzIzWjAjBgkqhkiG9w0BCQQxFgQU
XXav94EyMzVLpU677g2tnVswQQMwCQYHKoZIzjgEAwQuMCwCFFi2iMURcqtcbbWWuUxHSuui/QPU
AhR6pPGADhzHMf6I3FbYmEaP+xWHBQAAAAAAAA==`

	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)
	awsClient.EXPECT().GetPKCS7Signature().Return("i am not the configured pkcs7 signature!", nil)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: pkcs7,
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	vaultClient, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(vaultClient)
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), "Error making API request.\n\nURL: PUT http://127.0.0.1"+server.Addr+"/v1/auth/aws/login\nCode: 400. Raw Message:\n\n* client nonce mismatch\n")
}

// // TestClientFactoryAWSEC2Auth_WithClient_NonEC2 simulates
// // a situation when the EC2 authentication method is used
// // on a on a non-EC2 instance. This test checks that in such
// // a situation, the appropriate error is returned.
func TestClientFactoryAWSEC2Auth_WithClient_NotEC2(t *testing.T) {
	const role = "dev-role-ec2"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	awsClient := mock_aws.NewMockClient(ctrl)

	pkcs7Error := fmt.Errorf("%s\n%s %s", "RequestError: send request failed",
		"caused by: Get http://169.254.169.254/latest/dynamic/instance-identity/pkcs7:",
		"dial tcp 169.254.169.254:80: connect: no route to host")
	awsClient.EXPECT().GetPKCS7Signature().Return("", pkcs7Error)

	server, _ := test.MakeMockVaultServerEC2Auth(t, &test.TestVaultServerOptions{
		Role:  role,
		PKCS7: "hello darkness my old friend",
	})
	go server.ListenAndServe()
	defer server.Close()

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1%s", server.Addr))

	factory := ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: "aws",
	}

	vaultClient, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = factory.WithClient(vaultClient)
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	test.ErrorsEqual(t, err.Error(), pkcs7Error.Error())
}

func TestNewClientFactoryAWSEC2Auth_Success(t *testing.T) {
	os.Setenv("AWS_CONFIG_FILE", "file_not_exists")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "file_not_exists")
	test.SetTestAWSEnvVars()

	_, err := NewClientFactoryAWSEC2Auth("", "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewClientFactoryAWSEC2Auth_SessionError(t *testing.T) {
	// Backwards compatibility with Shared config disabled
	// assume role should not be built into the config.
	os.Setenv("AWS_CONFIG_FILE", "file_not_exists")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "file_not_exists")
	os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", "testdata/shared_config")
	os.Setenv("AWS_PROFILE", "assume_role_invalid_source_profile")

	_, err := NewClientFactoryAWSEC2Auth("", "")
	if err == nil {
		t.Fatal("Expected to receive an error but didn't")
	}

	os.Unsetenv("AWS_CONFIG_FILE")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_SDK_LOAD_CONFIG")
	os.Unsetenv("AWS_SHARED_CREDENTIALS_FILE")
	os.Unsetenv("AWS_PROFILE")

	test.ErrorsEqual(t, err.Error(), "error creating new AWS client: SharedConfigAssumeRoleError: failed to load assume role for assume_role_invalid_source_profile_role_arn, source profile has no shared credentials")
}

func TestMain(m *testing.M) {
	path := os.Getenv("PATH")
	env := awstesting.StashEnv()
	os.Setenv("PATH", path)
	defer awstesting.PopEnv(env)
	os.Exit(m.Run())
}
