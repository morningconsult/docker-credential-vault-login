package vault

import (
        "bytes"
        "encoding/json"
        "fmt"
        "net/http"
        "strconv"
        "testing"
        "time"

        cleanhttp "github.com/hashicorp/go-cleanhttp"
)

var VaultDevPortString string

var VaultDevRootToken string

func InitSecretsEngine(t *testing.T) (string, string) {
        if _, err := strconv.Atoi(VaultDevPortString); err != nil {
                t.Fatal("Vault listener port must be an integer")
        }
        if VaultDevRootToken == "" {
                t.Fatal("No Vault root token provided")
        }
        client := cleanhttp.DefaultClient()
        client.Timeout = time.Second * 60

        URL := fmt.Sprintf("http://127.0.0.1:%s/v1/sys/mounts/secret", VaultDevPortString)

        disableSecretEngine(t, client, URL, VaultDevRootToken)
        enableSecretEngine(t, client, URL, VaultDevRootToken)
        return fmt.Sprintf("http://127.0.0.1:%s", VaultDevPortString), VaultDevRootToken
}

func disableSecretEngine(t *testing.T, client *http.Client, URL, token string) {
        req, err := http.NewRequest("DELETE", URL, nil)
        if err != nil {
                t.Fatalf("error creating HTTP request object: %v", err)
        }
        req.Header.Set("X-Vault-Token", token)

        resp, err := client.Do(req)
        if err != nil {
                t.Fatalf("error making HTTP request: %v", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 204 {
                t.Fatalf("DELETE %s failed: %v", URL, err)
        }
}

func enableSecretEngine(t *testing.T, client *http.Client, URL, token string) {
        var params = map[string]interface{}{
                "type":    "kv",
                "options": map[string]string{
                        "version": "1",
                },
        }

        data, err := json.Marshal(params)
        if err != nil {
                t.Fatalf("error marshaling payload: %v", err)
        }

        req, err := http.NewRequest("POST", URL, bytes.NewBuffer(data))
        if err != nil {
                t.Fatalf("error creating HTTP request object: %v", err)
        }
        req.Header.Set("X-Vault-Token", token)
        req.Header.Set("Content-Type", "application/json")

        resp, err := client.Do(req)
        if err != nil {
                t.Fatalf("error making HTTP request: %v", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 204 {
                t.Fatalf("POST %s failed: %v", URL, err)
        }
}
