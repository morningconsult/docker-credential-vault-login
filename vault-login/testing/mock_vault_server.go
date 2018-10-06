// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//         https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path"
	"strings"
	"testing"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/phayes/freeport"
)

const defaultTestTTL int = 86400

type TestVaultServerOptions struct {
	SecretPath string
	Secret     map[string]interface{}
	Role       string
	PKCS7      string
}

type TestIAMAuthReqPayload struct {
	Role    string
	Method  string `json:"iam_http_request_method"`
	Url     string `json:"iam_request_url"`
	Body    string `json:"iam_request_body"`
	Headers string `json:"iam_request_headers"`
}

type TestEC2AuthReqPayload struct {
	Role  string
	PKCS7 string
}

// MakeMockVaultServerIAMAuth creates a mock Vault server which mimics two HTTP endpoints -
// /v1/auth/aws/login and /v1/<secret_path>. The purpose of this mock Vault server
// is to test Vault's AWS IAM authentication endpoint without having to actually
// make a real sts:GetCallerIdentity request to AWS. The behavior of the mimicked
// endpoints is configured via the testVaultServerOptions parameter. The login
// endpoint will only return 200 when the JSON payload of an HTTP request for this
// endpoint is properly structured and contains the expected data (see the IAM
// authentication information provided at
// https://www.vaultproject.io/api/auth/aws/index.html#login) and when the
// "role" field of the JSON payload matches the "role" field of the
// testVaultServerOptions object passed to MakeMockVaultServerIAMAuth. The value of
// <secret_path> in the other endpoint is specified by the secretPath field of
// the testVaultServerOptions object. For example, if opts.secretPath == "secret/foo",
// your secret (specified via the "secret") field of the testVaultServerOptions
// object can be read via GET http://127.0.0.1:<port>/v1/secret/foo.
func MakeMockVaultServerIAMAuth(t *testing.T, opts *TestVaultServerOptions) (*http.Server, string) {
	port, err := freeport.GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	token, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/aws/login", iamAuthHandler(t, opts.Role, token, port))
	if opts.SecretPath != "" {
		mux.HandleFunc(path.Join("/v1", opts.SecretPath), dockerSecretHandler(t, opts.Secret, token, port))
	}
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	return server, token
}

// MakeMockVaultServerEC2Auth creates a mock Vault server which mimics two HTTP
// endpoints - /v1/auth/aws/login and /v1/<secret_path>. The purpose of this mock
// Vault server is to test Vault's AWS EC2 authentication endpoint without having
// to actually make a real call to AWS. The behavior of the mimicked endpoints is
// configured via the TestVaultServerOptions parameter. The login endpoint will
// only return 200 when the JSON payload of an HTTP request for this endpoint
// (1)is  properly structured, (2) contains the fields ("role" and "pkcs7"),
// (3) the pkcs7 signature matches the value of the pkcs7 signature passed to
// MakeMockVaultServerEC2Auth, and (4) the "role" field of the JSON payload matches
//  the "role" field of the TestVaultServerOptions object passed to
// MakeMockVaultServerEC2Auth. This fourth condition mimics the behavior of Vault
// in requiring a given role attempting to login via the AWS EC2 endpoint to have
// been explicitly configured to be able to do so. The value of <secret_path> in
// the other endpoint is specified by the secretPath field of the
// TestVaultServerOptions object. For example, if opts.secretPath == "secret/foo",
// your secret (specified via the "secret") field of the TestVaultServerOptions
// object can be read via GET http://127.0.0.1:<port>/v1/secret/foo.
func MakeMockVaultServerEC2Auth(t *testing.T, opts *TestVaultServerOptions) (*http.Server, string) {
	port, err := freeport.GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	token, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/aws/login", ec2AuthHandler(t, opts.Role, token, opts.PKCS7, port))
	if opts.SecretPath != "" {
		mux.HandleFunc(path.Join("/v1", opts.SecretPath), dockerSecretHandler(t, opts.Secret, token, port))
	}
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	return server, token
}

func MakeMockVaultServerWithExistingToken(t *testing.T, pathToSecret string, secret map[string]interface{}, token string) *http.Server {
	port, err := freeport.GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path.Join("/v1", pathToSecret), dockerSecretHandler(t, secret, token, port))
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	return server
}

func dockerSecretHandler(t *testing.T, secret map[string]interface{}, token string, port int) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "GET":
			prefix := fmt.Sprintf("[ GET http://127.0.0.1:%d/v1/auth/aws/login ]", port)
			clientToken := req.Header.Get("X-Vault-Token")
			if clientToken == "" {
				t.Logf("%s request has no Vault token header\n", prefix)
				http.Error(resp, "", 400)
				return
			}

			if clientToken != token {
				http.Error(resp, "Unauthorized", 401)
				return
			}

			respData := &api.Secret{
				Data: secret,
			}

			payload, err := jsonutil.EncodeJSON(respData)
			if err != nil {
				t.Logf("%s error encoding JSON response payload: %v\n", prefix, err)
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

func iamAuthHandler(t *testing.T, role, token string, port int) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "POST", "PUT":
			prefix := fmt.Sprintf("[ POST http://127.0.0.1:%d/v1/auth/aws/login ]", port)

			var data = new(TestIAMAuthReqPayload)
			if err := jsonutil.DecodeJSONFromReader(req.Body, data); err != nil {
				t.Errorf("%s error unmarshaling response: %v\n", prefix, err)
				http.Error(resp, "", 500)
				return
			}

			if strings.ToLower(data.Role) != strings.ToLower(role) {
				http.Error(resp, fmt.Sprintf("* entry for role %q not found", data.Role), 400)
				return
			}

			if strings.ToLower(data.Method) != "post" {
				http.Error(resp, "", 400)
				return
			}

			url, err := base64.StdEncoding.DecodeString(data.Url)
			if err != nil {
				http.Error(resp, "", 400)
				return
			}

			if strings.TrimSuffix(string(url), "/") != "https://sts.amazonaws.com" {
				http.Error(resp, "", 400)
				return
			}

			databody, err := base64.StdEncoding.DecodeString(data.Body)
			if err != nil {
				http.Error(resp, "", 400)
				return
			}
			if string(databody) != "Action=GetCallerIdentity&Version=2011-06-15" {
				http.Error(resp, "", 400)
				return
			}

			headersBuf, err := base64.StdEncoding.DecodeString(data.Headers)
			if err != nil {
				http.Error(resp, "", 400)
				return
			}

			var headers = make(map[string][]string)
			if err = jsonutil.DecodeJSON(headersBuf, &headers); err != nil {
				http.Error(resp, "", 400)
				return
			}

			if _, ok := headers["Authorization"]; !ok {
				http.Error(resp, "", 400)
				return
			}

			respData := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   token,
					LeaseDuration: defaultTestTTL,
					Renewable:     true,
				},
			}

			payload, err := jsonutil.EncodeJSON(respData)
			if err != nil {
				t.Errorf("%s error marshaling response payload: %v\n", prefix, err)
				http.Error(resp, "", 500)
				return
			}

			resp.Header().Set("Content-Type", "application/json")
			resp.Write(payload)
			return
		default:
			http.Error(resp, "", 405)
			return
		}
	}
}

func ec2AuthHandler(t *testing.T, role, token, pkcs7 string, port int) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case "POST", "PUT":
			prefix := fmt.Sprintf("[ POST http://127.0.0.1:%d/v1/auth/aws/login ]", port)

			var data = new(TestEC2AuthReqPayload)
			if err := jsonutil.DecodeJSONFromReader(req.Body, data); err != nil {
				t.Errorf("%s error unmarshaling response: %v\n", prefix, err)
				http.Error(resp, "", 500)
				return
			}

			if strings.ToLower(data.Role) != strings.ToLower(role) {
				http.Error(resp, fmt.Sprintf("* entry for role %q not found", data.Role), 400)
				return
			}

			if strings.Replace(pkcs7, "\n", "", -1) != data.PKCS7 {
				http.Error(resp, "* client nonce mismatch", 400)
				return
			}

			respData := &api.Secret{
				Auth: &api.SecretAuth{
					ClientToken:   token,
					LeaseDuration: defaultTestTTL,
					Renewable:     true,
				},
			}

			payload, err := jsonutil.EncodeJSON(respData)
			if err != nil {
				t.Errorf("%s error marshaling response payload: %v\n", prefix, err)
				http.Error(resp, "", 500)
				return
			}

			resp.Header().Set("Content-Type", "application/json")
			resp.Write(payload)
			return
		default:
			http.Error(resp, "", 405)
			return
		}
	}
}
