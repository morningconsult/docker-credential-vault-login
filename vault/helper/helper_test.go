package helper

import (
        "bytes"
        "encoding/json"
        "io/ioutil"
        "net/http"
        "testing"
        "time"

        cleanhttp "github.com/hashicorp/go-cleanhttp"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
)

func TestTODO(t *testing.T) {
        var secret = "foo/bar"
        client := cleanhttp.DefaultClient()
        client.Timeout = time.Second * 60

        info := vault.NewVaultTestServerInfo(t)

        data, err := json.Marshal(map[string]interface{}{
                "data": map[string]string{
                        "foo": "bar"
                },
        })
        if err != nil {
                t.Fatalf("error marshaling map: %v", err)
        }
        buf := bytes.NewBuffer(data)

        req, err := http.NewRequest("PUT", info.Address + "/v1/secret/data/" + secret, buf)
        resp, err := client.Do(req)
        if err != nil {
                t.Fatalf("error making HTTP request: %v", err)
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                t.Fatalf("error reading response body: %v", err)
        }
        t.Logf("response body: %s\n", string(body))
}
