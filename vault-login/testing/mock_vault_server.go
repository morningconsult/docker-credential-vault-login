package test

import (
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "net/http"
        "path"
        "strings"
        "testing"

        "github.com/hashicorp/vault/api"
        uuid "github.com/hashicorp/go-uuid"
        "github.com/phayes/freeport"
)

type TestVaultServerOptions struct {
        SecretPath string
        Secret     map[string]interface{}
        Role       string
}

type TestAwsAuthReqPayload struct {
        Role    string `json:"role"`
        Method  string `json:"iam_http_request_method"`
        Url     string `json:"iam_request_url"`
        Body    string `json:"iam_request_body"`
        Headers string `json:"iam_request_headers"`
}

// makeMockVaultServer creates a mock Vault server which mimics two HTTP endpoints - 
// /v1/auth/aws/login and /v1/<secret_path>. The purpose of this mock Vault server
// is to test Vault's AWS IAM authentication endpoint without having to actually
// make a real STS GetCallerIdentity request to AWS. The behavior of the mimicked
// endpoints is configured via the testVaultServerOptions parameter. The login
// endpoint will only return 200 when the JSON payload of an HTTP request for this 
// endpoint is properly structured and contains the expected data (see the IAM
// authentication information provided at 
// https://www.vaultproject.io/api/auth/aws/index.html#login) and when the 
// "role" field of the JSON payload matches the "role" field of the 
// testVaultServerOptions object passed to makeMockVaultServer. The value of
// <secret_path> in the other endpoint is specified by the secretPath field of
// the testVaultServerOptions object. For example, if opts.secretPath == "secret/foo",
// your secret (specified via the "secret") field of the testVaultServerOptions
// object can be read via GET http://127.0.0.1:<port>/v1/secret/foo.
func MakeMockVaultServer(t *testing.T, opts *TestVaultServerOptions) *http.Server {
        port, err := freeport.GetFreePort()
        if err != nil {
                t.Fatal(err)
        }
        mux := http.NewServeMux()
        mux.HandleFunc("/v1/auth/aws/login", awsAuthHandler(t, opts.Role, port))
        mux.HandleFunc(path.Join("/v1", opts.SecretPath), dockerSecretHandler(t, opts.Secret, port))
        server := &http.Server{
                Addr:    fmt.Sprintf(":%d", port),
                Handler: mux,
        }
        return server
}

func dockerSecretHandler(t *testing.T, secret map[string]interface{}, port int) http.HandlerFunc {
        return func(resp http.ResponseWriter, req *http.Request) {
                switch req.Method {
                case "GET":
                        prefix := fmt.Sprintf("[ GET http://127.0.0.1:%d/v1/auth/aws/login ]", port)
                        token := req.Header.Get("X-Vault-Token")
                        if token == "" {
                                t.Logf("%s request has no Vault token header\n", prefix)
                                http.Error(resp, "", 400)
                                return
                        }
                        if _, err := uuid.ParseUUID(token); err != nil {
                                t.Logf("%s unable to parse token %q: %v", prefix, token, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        respData := &api.Secret{
                                Data: secret,
                        }

                        payload, err := json.Marshal(respData)
                        if err != nil {
                                t.Logf("%s error marshaling response payload: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        resp.Header().Set("Content-Type", "application/json")
                        if _, err = resp.Write(payload); err != nil {
                                t.Logf("%s error writing response: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                        }
                        return
                default:
                        http.Error(resp, "", 405)
                        return 
                }
        }
}

func awsAuthHandler(t *testing.T, role string, port int) http.HandlerFunc {
        return func(resp http.ResponseWriter, req *http.Request) {
                switch req.Method {
                case "POST", "PUT":
                        prefix := fmt.Sprintf("[ POST http://127.0.0.1:%d/v1/auth/aws/login ]", port)
                        body, err := ioutil.ReadAll(req.Body)
                        if err != nil {
                                t.Logf("%s error reading request body: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        var data = new(TestAwsAuthReqPayload)
                        // var datamap = make(map[string]interface{})
                        if err = json.Unmarshal(body, data); err != nil {
                                t.Logf("%s error unmarshaling response: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        if strings.ToLower(data.Role) != strings.ToLower(role) {
                                t.Logf("%s role %q not configured for AWS authentication\n", prefix, role)
                                http.Error(resp, "", 400)
                                return
                        }

                        if strings.ToLower(data.Method) != "post" {
                                t.Logf("%s \"iam_http_request_method\" method field of JSON payload is not \"POST\"\n", prefix)
                                http.Error(resp, "", 400)
                                return
                        }

                        url, err := base64.StdEncoding.DecodeString(data.Url)
                        if err != nil {
                                t.Logf("%s error base64 decoding \"iam_request_url\" field of JSON payload: %v\n", prefix, err)
                                http.Error(resp, "", 400)
                                return
                        }

                        if strings.TrimSuffix(string(url), "/") != "https://sts.amazonaws.com" {
                                t.Logf("%s \"iam_request_url\" field of JSON payload is not \"https://sts.amazonaws.com/\"\n", prefix)
                                http.Error(resp, "", 400)
                                return
                        }

                        databody, err := base64.StdEncoding.DecodeString(data.Body)
                        if err != nil {
                                t.Logf("%s error base64 decoding \"iam_request_body\" field of JSON payload: %v", prefix, err)
                                http.Error(resp, "", 400)
                                return
                        }
                        if string(databody) != "Action=GetCallerIdentity&Version=2011-06-15" {
                                t.Logf("%s \"iam_request_body\" field of JSON payload is not \"Action=GetCallerIdentity&Version=2011-06-15\"\n", prefix)
                                http.Error(resp, "", 400)
                                return
                        }

                        headersBuf, err := base64.StdEncoding.DecodeString(data.Headers)
                        if err != nil {
                                t.Logf("%s error base64 decoding \"iam_request_headers\" field of JSON payload: %v\n", prefix, err)
                                http.Error(resp, "", 400)
                                return
                        }
                        
                        var headers = make(map[string][]string)
                        if err = json.Unmarshal(headersBuf, &headers); err != nil {
                                t.Logf("%s error unmarshaling request headers: %v\n", prefix, err)
                                http.Error(resp, "", 400)
                                return
                        }

                        if _, ok := headers["Authorization"]; !ok {
                                t.Logf("%s \"iam_request_headers\" field of JSON payload has no \"Authorization\" header\n", prefix)
                                http.Error(resp, "", 400)
                                return
                        }
                        // return the expected response with random uuid
                        token, err := uuid.GenerateUUID()
                        if err != nil {
                                t.Logf("%s failed to create a random UUID: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        respData := &api.Secret{
                                Auth: &api.SecretAuth{
                                        ClientToken: token,
                                },
                        }

                        payload, err := json.Marshal(respData)
                        if err != nil {
                                t.Logf("%s error marshaling response payload: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                                return
                        }

                        resp.Header().Set("Content-Type", "application/json")
                        if _, err = resp.Write(payload); err != nil {
                                t.Logf("%s error writing response: %v\n", prefix, err)
                                http.Error(resp, "", 500)
                        }
                        return
                default:
                        http.Error(resp, "", 405)
                        return
                }
        }
}