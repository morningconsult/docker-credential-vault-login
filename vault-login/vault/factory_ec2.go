package vault

import (
	"path"
	"strings"
	"github.com/hashicorp/vault/api"
        "github.com/morningconsult/docker-credential-vault-login/vault-login/aws"
        "github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
        "github.com/morningconsult/docker-credential-vault-login/vault-login/config"
)

// ClientFactoryAWSEC2AuthConfig is used to set the
// value of the fields of a new ClientFactoryAWSEC2Auth
// object when passed to NewClientFactoryAWSEC2Auth().
type ClientFactoryAWSEC2AuthConfig struct {
        // Role is the Vault role associated with the IAM role
	// used in the sts:GetCallerIdentity request. This
	// Vault role should have permission to read the secret
	// specified in your config.json file.
        Role string

        // CacheUtil is used to access Vault tokens saved in
        // the cache.
        CacheUtil cache.CacheUtil
}

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

        // CacheUtil is used to access Vault tokens saved in
        // the cache.
        cacheUtil cache.CacheUtil
}

func NewClientFactoryAWSEC2Auth(config *ClientFactoryAWSEC2AuthConfig) (ClientFactory, error) {
	// Create a new AWS client
	awsClient, err := aws.NewDefaultClient()
	if err != nil {
		return nil, err
	}

	return &ClientFactoryAWSEC2Auth{
		awsClient: awsClient,
                role:      config.Role,
                cacheUtil: config.CacheUtil,
	}, nil
}

// NewClient creates a new Vault API client and uses it to attempt to
// authenticate against Vault via the AWS EC2 endpoint. If authentication
// is successful, it will set the Vault API client with the newly-created
// client token and return a DefaultClient object.
func (c *ClientFactoryAWSEC2Auth) NewClient() (Client, error) {
        // Create a new Vault API client
	vaultClient, err := api.NewClient(nil)
	if err != nil {
		return nil, err
        }

        // Attempt to get a cached token
        token, err := c.cacheUtil.GetCachedToken(config.VaultAuthMethodAWSEC2)
        if err != nil {
                return nil, err
        }

        // If cacheUtil.GetCachedToken() returned a token then
        // give it to vaultClient and return
        if token != "" {
                vaultClient.SetToken(token)
                return NewDefaultClient(vaultClient), nil
        }

	// Get the EC2 instance's PKCS7 signature and login to
	// Vault to obtain a token via Vault's AWS EC2 endpoint
	if err = c.getAndSetNewToken(vaultClient); err != nil {
		return nil, err
	}

	return NewDefaultClient(vaultClient), nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS EC2
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient
// object. This function is primarily used for testing purposes.
func (c *ClientFactoryAWSEC2Auth) WithClient(vaultClient *api.Client) (Client, error) {
        // Attempt to get a cached token
        token, err := c.cacheUtil.GetCachedToken(config.VaultAuthMethodAWSEC2)
        if err != nil {
                return nil, err
        }

        // If cacheUtil.GetCachedToken() returned a token then
        // give it to vaultClient and return
        if token != "" {
                vaultClient.SetToken(token)
                return NewDefaultClient(vaultClient), nil
        }

	// Get the EC2 instance's PKCS7 signature and login to
	// Vault to obtain a token via Vault's AWS EC2 endpoint
	if err := c.getAndSetNewToken(vaultClient); err != nil {
		return nil, err
	}

	return NewDefaultClient(vaultClient), nil
}

func (c *ClientFactoryAWSEC2Auth) getAndSetNewToken(vaultClient *api.Client) error {
	// Get the elements of the EC2 metadata required to
	// authenticate against Vault
	pkcs7, err := c.awsClient.GetPKCS7Signature()
	if err != nil {
		return err
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
		return err
	}

	// Set the client token to the API client
        vaultClient.SetToken(secret.Auth.ClientToken)
        
        err = c.cacheUtil.CacheNewToken(secret.Auth.ClientToken, secret.Auth.LeaseDuration, config.VaultAuthMethodAWSEC2)
        if err != nil {
                return err
        }
	return nil
}
