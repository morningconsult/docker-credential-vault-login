package vault

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "strconv"
        "strings"
        "testing"
        "time"

        cleanhttp "github.com/hashicorp/go-cleanhttp"
)

var VaultDevPortString string

var VaultDevRootToken string

type TestClient struct {
        pathPrefix string
        address    string
        token      string
        client     *http.Client
}

func NewTestClient(t *testing.T) *TestClient {
        if _, err := strconv.Atoi(VaultDevPortString); err != nil {
                t.Fatal("Vault listener port must be an integer")
        }
        if VaultDevRootToken == "" {
                t.Fatal("No Vault root token provided")
        }

        cl := cleanhttp.DefaultClient()
        cl.Timeout = time.Second * 60

        return &TestClient{
                pathPrefix: "/v1/secret/data",
                address:    "http://127.0.0.1:" + VaultDevPortString,
                token:      VaultDevRootToken,
                client:     cl,
        }
}

// path should be only the path to the secret. For example, if
// your secret is stored at "secret/foo/bar", you should pass
// only "foo/bar" as the path argument to this function.
func (c *TestClient) Write(t *testing.T, path string, data map[string]interface{}) *http.Response {
        var secret map[string]interface{}

        path = strings.TrimPrefix(path, "/")
        
        if hasData(secret) {
                secret = data
        } else {
                secret = map[string]interface{}{
                        "data": data,
                }
        }

        b, err := json.Marshal(secret)
        if err != nil {
                t.Fatalf("error marshaling secret: %v", err)
        }

        req, err := http.NewRequest("PUT", fmt.Sprintf("%s%s/%s", c.address, c.pathPrefix, path), bytes.NewBuffer(b))
        req.Header.Set("X-Vault-Token", c.token)
        req.Header.Set("Content-Type", "application/json")

        resp, err := c.client.Do(req)
        if err != nil {
                t.Fatalf("error making HTTP request: %v", err)
        }
        return resp
}

func (c *TestClient) Read(t *testing.T, path string) *http.Response {
        req, err := http.NewRequest("GET", fmt.Sprintf("%s%s/%s", c.address, c.pathPrefix, path), nil)
        req.Header.Set("X-Vault-Token", c.token)
        resp, err := c.client.Do(req)
        if err != nil {
                t.Fatalf("error making HTTP request: %v", err)
        }
        return resp
}

func hasData(data map[string]interface{}) bool {
        for k, _ := range data {
                if k == "data" {
                        return true
                }
        }
        return false
}