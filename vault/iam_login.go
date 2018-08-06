package vault

import (
        "bytes"
        "fmt"
        "encoding/base64"
        "encoding/json"
        "io/ioutil"
        "net/http"
        "os"
        "strings"
        "time"
        cleanhttp "github.com/hashicorp/go-cleanhttp"

        "gitlab.morningconsult.com/mci/docker-credential-vault-login/aws"
)

const (
        VaultAPIVersion int = 1

        VaultAPIAWSLoginEndpoint string = "/auth/aws/login"
)

func GetAndSetToken(role string) error {
        var addr string

        // Get Vault server URL from environment
        if addr = os.Getenv("VAULT_ADDR"); addr == "" {
                return fmt.Errorf("VAULT_ADDR is not set")
        }

        // Create an HTTP client
        client := makeHTTPClient()

        // Create parameters for an sts:GetCallerIdentity request
        elems, err := aws.GetIAMAuthElements()
        if err != nil {
                return err
        }

        // Build the request payload
        payload, err := makePayload(role, elems)
        if err != nil {
                return err
        }

        // Construct URL for Vault's AWS IAM login endpoint
        url := fmt.Sprintf("%s/v%d%s", strings.TrimRight(addr, "/"), 
                VaultAPIVersion, VaultAPIAWSLoginEndpoint)

        // Make login request to Vault
        resp, err := client.Post(url, "application/json", payload)
        if err != nil {
                return fmt.Errorf("error making AWS login HTTP request to Vault: %v", err)
        }
        defer resp.Body.Close()

        // Parse the response and extract the token
        token, err := extractToken(resp)
        if err != nil {
                return fmt.Errorf("error reading response body: %v", err)
        }

        // Set the value of the VAULT_TOKEN environment variable to
        // the value of the newly created Vault token
        os.Setenv("VAULT_TOKEN", token)

        return nil
}

func makeHTTPClient() *http.Client {
        client := cleanhttp.DefaultClient()
        client.Timeout = time.Second * 60
        return client
}

func makePayload(role string, elems *aws.IAMAuthElements) (*bytes.Buffer, error) {
        buf, err := json.Marshal(elems.Headers)
        if err != nil {
                return nil, err
        }
        headers := base64.StdEncoding.EncodeToString(buf)
        url := base64.StdEncoding.EncodeToString([]byte(elems.URL))
        body := base64.StdEncoding.EncodeToString([]byte(elems.Body))

        p := map[string]string{
                "role":                    role,
                "iam_http_request_method": elems.Method,
                "iam_request_url":         url,
                "iam_request_body":        body,
                "iam_request_headers":     headers,
        }

        pbuf, err := json.Marshal(p)
        if err != nil {
                return nil, err
        }
        payload := bytes.NewBuffer(pbuf)
        return payload, nil
}

func extractToken(resp *http.Response) (string, error) {
        var (
                auth  map[string]interface{}
                token string
                ok    bool
        )

        body, err := readResponseBody(resp)
        if err != nil {
                return "", err
        }

        if auth, ok = body["auth"].(map[string]interface{}); !ok {
                return "", fmt.Errorf("unable to read \"auth\" field of JSON response body")
        }

        if token, ok = auth["client_token"].(string); !ok {
                return "", fmt.Errorf("unable to read \"client_token\" field of JSON response body")
        }

        return token, nil
}

func readResponseBody(resp *http.Response) (map[string]interface{}, error) {
        buf, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                return nil, err
        }
        body := make(map[string]interface{})
        err = json.Unmarshal(buf, &body)
        return body, err
}
