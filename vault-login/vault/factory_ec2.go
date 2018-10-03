package vault

import (
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/aws"
	"path"
	"strings"
)

// ClientFactoryAWSEC2Auth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained by
// authenticating against Vault via its AWS EC2 endpoint.
type ClientFactoryAWSEC2Auth struct {
	// awsClient is used to call AWS functions as needed
	// to obtain the information necessary to authenticate
	// against Vault via the AWS login endpoint
	awsClient aws.Client

	// role is the Vault role associated with the
	// IAM role used in the sts:GetCallerIdentity request. This
	// Vault role should have permission to read the secret
	// specified in your config.json file.
	role string
}

func NewClientFactoryAWSEC2Auth(role string) (ClientFactory, error) {
	// Create a new AWS client
	awsClient, err := aws.NewDefaultClient()
	if err != nil {
		return nil, err
	}

	return &ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
		role:      role,
	}, nil
}

// NewClient creates a new Vault API client and uses it to attempt to
// authenticate against Vault via the AWS EC2 endpoint. If authentication
// is successful, it will set the Vault API client with the newly-created
// client token and return a DefaultClient object.
func (c *ClientFactoryAWSEC2Auth) NewClient() (Client, *api.Secret, error) {
	// Create a new Vault API client
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		return nil, nil, err
	}

	// Get the EC2 instance's PKCS7 signature and login to
	// Vault to obtain a token via Vault's AWS EC2 endpoint
	secret, err := c.getAndSetNewToken(vaultClient)
	if err != nil {
		return nil, nil, err
	}

	return NewDefaultClient(vaultClient), secret, nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS EC2
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient
// object. This function is primarily used for testing purposes.
func (c *ClientFactoryAWSEC2Auth) WithClient(vaultClient *api.Client) (Client, *api.Secret, error) {
	// Get the EC2 instance's PKCS7 signature and login to
	// Vault to obtain a token via Vault's AWS EC2 endpoint
	secret, err := c.getAndSetNewToken(vaultClient)
	if err != nil {
		return nil, nil, err
	}

	return NewDefaultClient(vaultClient), secret, nil
}

func (c *ClientFactoryAWSEC2Auth) getAndSetNewToken(vaultClient *api.Client) (*api.Secret, error) {
	// Get the elements of the EC2 metadata required to
	// authenticate against Vault
	pkcs7, err := c.awsClient.GetPKCS7Signature()
	if err != nil {
		return nil, err
	}

	// Create request payload
	payload := map[string]interface{}{
		"role":  c.role,
		"pkcs7": strings.Replace(pkcs7, "\n", "", -1),
	}

	// Authenticate against Vault via the AWS EC2 endpoint
	// in order to obtain a valid client token
	secret, err := vaultClient.Logical().Write(path.Join("auth", "aws", "login"), payload)
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
