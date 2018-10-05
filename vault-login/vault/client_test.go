package vault

import (
	test "github.com/morningconsult/docker-credential-vault-login/vault-login/testing"
	"testing"
)

func TestGetCredentials(t *testing.T) {
	var (
		username = "frodo.baggins@theshire.com"
		password = "potatoes"
	)

	cluster := test.StartTestCluster(t)
	defer cluster.Cleanup()

	client := NewDefaultClient(test.NewPreConfiguredVaultClient(t, cluster))

	cases := []struct{
		name        string
		actualPath  string
		requestPath string
		secret      map[string]interface{}
		err         bool
	}{
		{
			"success",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"username": username,
				"password": password,
			},
			false,
		},
		{
			"wrong-path",
			"secret/foo/bar",
			"secret/bim/baz",
			map[string]interface{}{
				"username": username,
				"password": password,
			},
			true,
		},
		{
			"no-username",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"password": password,
			},
			true,
		},
		{
			"no-password",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"username": username,
			},
			true,
		},
		{
			"no-creds",
			"secret/foo/bar",
			"secret/foo/bar",
			map[string]interface{}{
				"user": username,
				"pw":   password,
			},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.WriteSecret(t, client.(*DefaultClient).RawClient(), tc.actualPath, tc.secret)

			creds, err := client.GetCredentials(tc.requestPath)

			if tc.err {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				return
			}

			if creds.Username != username {
				t.Fatalf("Unexpected username (expected %q, got %q)", username, creds.Username)
			}
			if creds.Password != password {
				t.Fatalf("Unexpected password (expected %q, got %q)", password, creds.Password)
			}
		})
	}
}
