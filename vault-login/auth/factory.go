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

package auth

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/aws"
	"path"
	"strings"
)

// ClientFactory is used to create a new Client instance. Authenticate() will
// attempt to obtain a valid Vault token via the authentication method specified
// in the config.json file and give it to the Vault API client
type ClientFactory interface {

	// NewClient receives a Vault API client and attempts to give it a token using
	// the method specified in the config.json file. This method is primarily for
	// testing purposes
	Authenticate(*api.Client) (Client, *api.Secret, error)
}

// ClientFactoryAWSEC2Auth is used to either create a new Vault API client with
// a valid Vault token or to give an existing Vault API client a valid token.
// The token is obtained by authenticating against Vault via its AWS EC2
// endpoint.
type ClientFactoryAWSEC2Auth struct {

	// awsClient is used to call AWS functions as needed to obtain the
	// information necessary to authenticate against Vault via the AWS
	// login endpoint
	awsClient aws.Client

	// role is the Vault role associated with the IAM role used in the
	// sts:GetCallerIdentity request. This Vault role should have permission
	// to read the secret specified in your config.json file.
	role string

	// (optional) mountPath specifies path at which the AWS secrets engine
	// was enabled (if at all) in your Vault server. If empty, it will use
	// the default value of "aws"
	mountPath string
}

func NewClientFactoryAWSEC2Auth(role, mountPath string) (ClientFactory, error) {
	// Create a new AWS client
	awsClient, err := aws.NewDefaultClient()
	if err != nil {
		return nil, err
	}

	return &ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
		mountPath: mountPath,
	}, nil
}

// Authenticate receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS EC2
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a new
// DefaultClient instance
func (c *ClientFactoryAWSEC2Auth) Authenticate(vaultClient *api.Client) (Client, *api.Secret, error) {
	// Clear the client token
	vaultClient.ClearToken()

	// Get the elements of the EC2 metadata required to
	// authenticate against Vault
	pkcs7, err := c.awsClient.GetPKCS7Signature()
	if err != nil {
		return nil, nil, err
	}

	// Create request payload
	payload := map[string]interface{}{
		"role":  c.role,
		"pkcs7": strings.Replace(pkcs7, "\n", "", -1),
	}

	// Authenticate against Vault via the AWS EC2 endpoint
	// in order to obtain a valid client token
	token, secret, err := makeRequest(vaultClient, c.mountPath, payload)
	if err != nil {
		return nil, nil, err
	}

	// Set the client token to the API client
	vaultClient.SetToken(token)

	return NewDefaultClient(vaultClient), secret, nil
}

// ClientFactoryAWSEC2Auth is used to either create a new Vault API client with
// a valid Vault token or to give an existing Vault API client a valid token.
// The token is obtained by authenticating against Vault via its AWS IAM endpoint.
type ClientFactoryAWSIAMAuth struct {

	// awsClient is used to call AWS functions as needed to obtain the
	// information necessary to authenticate against Vault via the AWS
	// login endpoint.
	awsClient aws.Client

	// role is the Vault role associated with the IAM role used in the
	// sts:GetCallerIdentity request. This Vault role should have permission
	// to read the secret specified in your config.json file.
	role string

	// (Optional) serverID is the name of the Vault server to be used as the
	// value of the X-Vault-AWS-IAM-Server-ID header in the
	// sts:GetCallerIdentity request.
	serverID string

	// (optional) mountPath specifies path at which the AWS secrets engine
	// was enabled (if at all) in your Vault server. If empty, it will use
	// the default value of "aws"
	mountPath string
}

func NewClientFactoryAWSIAMAuth(role, serverID, mountPath string) (ClientFactory, error) {
	// Create a new AWS client
	awsClient, err := aws.NewDefaultClient()
	if err != nil {
		return nil, err
	}

	return &ClientFactoryAWSIAMAuth{
		awsClient: awsClient,
		role:      role,
		serverID:  serverID,
		mountPath: mountPath,
	}, nil
}

// Authenticate receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS IAM
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a new DefaultClient
// instance
func (c *ClientFactoryAWSIAMAuth) Authenticate(vaultClient *api.Client) (Client, *api.Secret, error) {
	// Clear the client token
	vaultClient.ClearToken()

	// Create an sts:GetCallerIdentity request and return the elements
	// of the request needed for Vault to authenticate against IAM
	elems, err := c.awsClient.GetIAMAuthElements(c.serverID)
	if err != nil {
		return nil, nil, err
	}

	// Build the request payload
	buf, err := jsonutil.EncodeJSON(elems.Headers)
	if err != nil {
		return nil, nil, err
	}

	// Create request payload
	payload := map[string]interface{}{
		"role":                    c.role,
		"iam_http_request_method": elems.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(elems.URL)),
		"iam_request_body":        base64.StdEncoding.EncodeToString(elems.Body),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(buf),
	}

	// Authenticate against Vault via the AWS IAM endpoint
	// in order to obtain a valid client token
	token, secret, err := makeRequest(vaultClient, c.mountPath, payload)
	if err != nil {
		return nil, nil, err
	}

	// Set the client token to the API client
	vaultClient.SetToken(token)

	return NewDefaultClient(vaultClient), secret, nil
}

func makeRequest(client *api.Client, mountPath string, payload map[string]interface{}) (string, *api.Secret, error) {
	secret, err := client.Logical().Write(path.Join("auth", mountPath, "login"), payload)
	if err != nil {
		return "", nil, err
	}

	if secret == nil {
		return "", nil, fmt.Errorf("received no data in response to authentication request")
	}

	token, err := secret.TokenID()
	if err != nil {
		return "", nil, fmt.Errorf("error reading token from secret: %v", err)
	}

	if token == "" {
		return "", nil, fmt.Errorf("no token received in response to authentication request")
	}

	return token, secret, nil
}
