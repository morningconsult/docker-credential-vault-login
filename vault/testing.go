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
        t          *testing.T
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
                t:          t,
        }
}

func (c *TestClient) InitSecretsEngine() {
        c.disableSecretEngine()
        c.enableSecretEngine()
}

func (c *TestClient) disableSecretEngine() {
        req, err := http.NewRequest("DELETE", c.address + "/v1/sys/mounts/secret", nil)
        if err != nil {
                c.t.Fatalf("error creating HTTP request object: %v", err)
        }
        req.Header.Set("X-Vault-Token", c.token)
        resp, err := c.client.Do(req)
        if err != nil {
                c.t.Fatalf("error making HTTP request: %v", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != 204 {
                c.t.Fatal("DELETE /v1/sys/mounts/secret failed: %v", err)
        }
}

func (c *TestClient) enableSecretEngine() {
        var params = map[string]interface{}{
                "type":    "kv",
                "options": map[string]string{
                        "version": "1",
                },
        }
        data, err := json.Marshal(params)
        if err != nil {
                c.t.Fatalf("error marshaling payload: %v", err)
        }
        req, err := http.NewRequest("POST", c.address + "/v1/sys/mounts/secret", bytes.NewBuffer(data))
        if err != nil {
                c.t.Fatalf("error creating HTTP request object: %v", err)
        }
        req.Header.Set("X-Vault-Token", c.token)
        req.Header.Set("Content-Type", "application/json")
        resp, err := c.client.Do(req)
        if err != nil {
                c.t.Fatalf("error making HTTP request: %v", err)
        }
        defer resp.Body.Close()
        if resp.StatusCode != 204 {
                c.t.Fatalf("POST /v1/sys/mounts/secret failed: %v", err)
        }
}

func (c *TestClient) Write(path string, data map[string]interface{}) *http.Response {
        var secret map[string]interface{}

        path = strings.TrimPrefix(strings.TrimPrefix(path, "/"), "secret/")

        if hasData(secret) {
                secret = data
        } else {
                secret = map[string]interface{}{
                        "data": data,
                }
        }

        b, err := json.Marshal(secret)
        if err != nil {
                c.t.Fatalf("error marshaling secret: %v", err)
        }

        req, err := http.NewRequest("PUT", fmt.Sprintf("%s%s/%s", c.address, c.pathPrefix, path), bytes.NewBuffer(b))
        if err != nil {
                t.Fatalf("error creating HTTP request object: %v", err)
        }
        req.Header.Set("X-Vault-Token", c.token)
        req.Header.Set("Content-Type", "application/json")

        resp, err := c.client.Do(req)
        if err != nil {
                c.t.Fatalf("error making HTTP request: %v", err)
        }
        return resp
}

func (c *TestClient) Read(path string) *http.Response {

        path = strings.TrimPrefix(strings.TrimPrefix(path, "/"), "secret/")

        req, err := http.NewRequest("GET", fmt.Sprintf("%s%s/%s", c.address, c.pathPrefix, path), nil)
        req.Header.Set("X-Vault-Token", c.token)
        resp, err := c.client.Do(req)
        if err != nil {
                c.t.Fatalf("error making HTTP request: %v", err)
        }
        return resp
}

func (c *TestClient) Token() string {
        return c.token
}

func (c *TestClient) Address() string {
        return c.address
}

func hasData(data map[string]interface{}) bool {
        for k, _ := range data {
                if k == "data" {
                        return true
                }
        }
        return false
}
