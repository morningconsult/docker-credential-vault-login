package helper

import (
        "io/ioutil"
        "testing"

        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

func TestTODO(t *testing.T) {
        var secret = "foo/bar"

        client := vault.NewTestClient(t)

        resp := client.Write(secret, map[string]interface{}{"foo": "bar"})
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                t.Fatalf("error reading HTTP response body: %v", err)
        }
        t.Logf("Body: %s\n", string(body))
}
