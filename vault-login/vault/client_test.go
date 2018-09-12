package vault

import (
        "fmt"
        "testing"
        test "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/testing"
)

func TestGetCredentials_Success(t *testing.T) {
        var (
                username = "frodo.baggins@theshire.com"
                password = "potatoes"
                secretPath = "secret/foo/bar"
                secret = map[string]interface{}{
                        "username": username,
                        "password": password,
                }
        )

        cluster := test.StartTestCluster(t)
        defer cluster.Cleanup()

        client := test.NewPreConfiguredVaultClient(t, cluster)

        test.WriteSecret(t, client, secretPath, secret)

        appClient := NewDefaultClient(client)

        creds, err := appClient.GetCredentials(secretPath)
        if err != nil {
                t.Fatal(err)
        }
        if creds.Username != username {
                t.Fatalf("Unexpected username (expected %q, got %q)", username, creds.Username)
        }
        if creds.Password != password {
                t.Fatalf("Unexpected password (expected %q, got %q)", password, creds.Password)
        }
}

// TestGetCredentials_WrongPath tests that if the client attempts to read
// a secret at an empty path (i.e. a path where no secret has been written)
// the client returns the appropriate error.
func TestGetCredentials_WrongPath(t *testing.T) {
        var fakePath = "secret/bim/baz"

        cluster := test.StartTestCluster(t)
        defer cluster.Cleanup()

        client := test.NewPreConfiguredVaultClient(t, cluster)

        appClient := NewDefaultClient(client)

        _, err := appClient.GetCredentials(fakePath)
        if err == nil {
                t.Fatal("expected an error, but got none")
        }

        expectedError := fmt.Sprintf("No secret found in Vault at path %q", fakePath)
        actualError := err.Error()
        if expectedError != actualError {
                t.Fatalf("expected error %q, got %q instead", expectedError, actualError)
        }
}

// TestGetCredentials_NoUsername tests that if the client attempts to read
// a secret without a "username" key, it returns the appropriate error.
func TestGetCredentials_NoUsername(t *testing.T) {
        var (
                secretPath = "secret/foo/bar"
                secret = map[string]interface{}{
                        "user": "frodo.baggins@theshire.com",
                        "password": "potatoes",
                }
        )

        cluster := test.StartTestCluster(t)
        defer cluster.Cleanup()

        client := test.NewPreConfiguredVaultClient(t, cluster)

        test.WriteSecret(t, client, secretPath, secret)

        appClient := NewDefaultClient(client)

        _, err := appClient.GetCredentials(secretPath)
        if err == nil {
                t.Fatal("expected an error, but got none")
        }

        expectedError := fmt.Sprintf("No username found in Vault at path %q", secretPath)
        actualError := err.Error()
        if expectedError != actualError {
                t.Fatalf("expected error %q, got %q instead", expectedError, actualError)
        }
}

// TestGetCredentials_NoPassword tests that if the client attempts to read
// a secret without a "password" key, it returns the appropriate error.
func TestGetCredentials_NoPassword(t *testing.T) {
        var (
                secretPath = "secret/foo/bar"
                secret = map[string]interface{}{
                        "username": "frodo.baggins@theshire.com",
                        "pw": "potatoes",
                }
        )

        cluster := test.StartTestCluster(t)
        defer cluster.Cleanup()

        client := test.NewPreConfiguredVaultClient(t, cluster)

        test.WriteSecret(t, client, secretPath, secret)

        appClient := NewDefaultClient(client)

        _, err := appClient.GetCredentials(secretPath)
        if err == nil {
                t.Fatal("expected an error, but got none")
        }

        expectedError := fmt.Sprintf("No password found in Vault at path %q", secretPath)
        actualError := err.Error()
        if expectedError != actualError {
                t.Fatalf("expected error %q, got %q instead", expectedError, actualError)
        }
}

// TestGetCredentials_NoCreds tests that if the client attempts to read
// a secret without a "username" or "password" key, it returns the
// appropriate error.
func TestGetCredentials_NoCreds(t *testing.T) {
        var (
                secretPath = "secret/foo/bar"
                secret = map[string]interface{}{
                        "user": "frodo.baggins@theshire.com",
                        "pw": "potatoes",
                }
        )

        cluster := test.StartTestCluster(t)
        defer cluster.Cleanup()

        client := test.NewPreConfiguredVaultClient(t, cluster)

        test.WriteSecret(t, client, secretPath, secret)

        appClient := NewDefaultClient(client)

        _, err := appClient.GetCredentials(secretPath)
        if err == nil {
                t.Fatal("expected an error, but got none")
        }

        expectedError := fmt.Sprintf("No username or password found in Vault at path %q", secretPath)
        actualError := err.Error()
        if expectedError != actualError {
                t.Fatalf("expected error %q, got %q instead", expectedError, actualError)
        }
}

// TestGetCredentials_WrongPath tests that if the client attempts to read
// a secret at an empty path (i.e. a path where no secret has been written)
// the client returns the appropriate error.
// func TestGetCredentials_(t *testing.T) {
//         var fakePath = "secret/bim/baz"

//         cluster := test.StartTestCluster(t)
//         defer cluster.Cleanup()

//         client := test.NewPreConfiguredVaultClient(t, cluster)

//         appClient := NewDefaultClient(client)

//         _, err := appClient.GetCredentials(fakePath)
//         if err == nil {
//                 t.Fatal("expected an error, but got none")
//         }

//         expectedError := fmt.Sprintf("No secret found in Vault at path %q", fakePath)
//         actualError := err.Error()
//         if expectedError != actualError {
//                 t.Fatalf("expected error %q, got %q instead", expectedError, actualError)
//         }
// }
