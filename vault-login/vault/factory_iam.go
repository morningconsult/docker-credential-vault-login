package vault

import (
	"encoding/base64"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/aws"
	"path"
)

// ClientFactoryAWSEC2Auth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained by
// authenticating against Vault via its AWS IAM endpoint.
type ClientFactoryAWSIAMAuth struct {
	// awsClient is used to call AWS functions as needed
	// to obtain the information necessary to authenticate
	// against Vault via the AWS login endpoint.
	awsClient aws.Client

	// role is the Vault role associated with the IAM role
	// used in the sts:GetCallerIdentity request. This
	// Vault role should have permission to read the secret
	// specified in your config.json file.
	role string

	// (Optional) serverID is the name of the Vault server
	// to be used as the value of the X-Vault-AWS-IAM-Server-ID
	// header in the sts:GetCallerIdentity request.
	serverID string

	// (optional) mountPath specifies path at which the AWS
	// secrets engine was enabled (if at all) in your Vault
	// server. If empty, it will use the default value of
	// "aws"
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

// NewClient creates a new Vault API client and uses it to attempt to
// authenticate against Vault via the AWS IAM endpoint. If authentication
// is successful, it will set the Vault API client with the newly-created
// client token and return a DefaultClient object.
func (c *ClientFactoryAWSIAMAuth) NewClient() (Client, *api.Secret, error) {
	// Create a new Vault API client
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		return nil, nil, err
	}

	// Build an sts:GetCallerIdentity request and login to
	// Vault to obtain a token via Vault's AWS IAM endpoint
	secret, err := c.getAndSetNewToken(vaultClient)
	if err != nil {
		return nil, nil, err
	}

	return NewDefaultClient(vaultClient), secret, nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS IAM
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient
// object. This function is primarily used for testing purposes.
func (c *ClientFactoryAWSIAMAuth) WithClient(vaultClient *api.Client) (Client, *api.Secret, error) {
	// Build an sts:GetCallerIdentity request and login to
	// Vault to obtain a token via Vault's AWS IAM endpoint
	secret, err := c.getAndSetNewToken(vaultClient)
	if err != nil {
		return nil, nil, err
	}

	return NewDefaultClient(vaultClient), secret, nil
}

// getAndSetNewToken creates an AWS sts:GetCallerIdentity request, gets the
// request elements required to authenticate against the Vault AWS IAM auth
// endpoint, makes the authentication request to Vault, and if successful it
// sets the token of Vault API client with the newly-created Vault token.
func (c *ClientFactoryAWSIAMAuth) getAndSetNewToken(vaultClient *api.Client) (*api.Secret, error) {
	// Create an sts:GetCallerIdentity request and return the elements
	// of the request needed for Vault to authenticate against IAM
	elems, err := c.awsClient.GetIAMAuthElements(c.serverID)
	if err != nil {
		return nil, err
	}

	// Build the request payload
	buf, err := jsonutil.EncodeJSON(elems.Headers)
	if err != nil {
		return nil, err
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
	secret, err := vaultClient.Logical().Write(path.Join("auth", c.mountPath, "login"), payload)
	if err != nil {
		return nil, err
	}

	// Get the token from the secret
	token, err := secret.TokenID()
	if err != nil {
		return nil, fmt.Errorf("error reading token from secret: %v", err)
	}

	// Set the client token to the API client
	vaultClient.SetToken(token)

	return secret, nil
}
