package vault

import (
        "fmt"
        "encoding/base64"
        "os"
        "path"
	"strings"

        "github.com/hashicorp/vault/api"
        "github.com/hashicorp/vault/helper/jsonutil"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/aws"
)

type ClientFactory interface {
        WithClient(*api.Client) (Client, error)
        NewClient() (Client, error)
}

// ClientFactoryAWSEC2Auth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained by
// authenticating against Vault via its AWS IAM endpoint.
type ClientFactoryAWSIAMAuth struct {
        // (Required) role is the Vault role associated with the
        // IAM role used in the sts:GetCallerIdentity request. This
        // Vault role should have permission to read the secret
        // specified in your config.json file.
        role string

        // (Optional) serverID is the name of the Vault server
        // to be used as the value of the X-Vault-AWS-IAM-Server-ID
        // header in the sts:GetCallerIdentity request.
        serverID string
}

func NewClientFactoryAWSIAMAuth(role, serverID string) ClientFactory {
        return &ClientFactoryAWSIAMAuth{
                role:     role,
                serverID: serverID,
        }
}

// NewClient creates a new Vault API client and uses it to attempt to
// authenticate against Vault via the AWS IAM endpoint. If authentication
// is successful, it will set the Vault API client with the newly-created
// client token and return a DefaultClient object.
func (c *ClientFactoryAWSIAMAuth) NewClient() (Client, error) {
        // Create a new Vault API client
        vaultClient, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }

        // Build an sts:GetCallerIdentity request and login to
        // Vault to obtain a token via Vault's AWS IAM endpoint
        if err = c.getAndSetToken(vaultClient); err != nil {
                return nil, err
        }

        return NewDefaultClient(vaultClient), nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS IAM
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient 
// object.
func (c *ClientFactoryAWSIAMAuth) WithClient(vaultClient *api.Client) (Client, error) {
        // Build an sts:GetCallerIdentity request and login to
        // Vault to obtain a token via Vault's AWS IAM endpoint
        if err := c.getAndSetToken(vaultClient); err != nil {
                return nil, err
        }

        return NewDefaultClient(vaultClient), nil
}

// getAndSetToken creates an AWS sts:GetCallerIdentity request, gets the
// request elements required to authenticate against the Vault AWS IAM auth
// endpoint, makes the authentication request to Vault, and if successful it
// sets the token of Vault API client with the newly-created Vault token. 
func (c *ClientFactoryAWSIAMAuth) getAndSetToken(vaultClient *api.Client) error {
        // Create a new AWS client
        awsClient, err := aws.NewDefaultClient()
        if err != nil {
                return err
        }

        // Create an sts:GetCallerIdentity request and return the elements
        // of the request needed for Vault to authenticate against IAM
        elems, err := awsClient.GetIAMAuthElements(c.serverID)
        if err != nil {
                return err
        }

        // Build the request payload
        buf, err := jsonutil.EncodeJSON(elems.Headers)
        if err != nil {
                return err
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
        secret, err := vaultClient.Logical().Write(path.Join("auth", "aws", "login"), payload)
        if err != nil {
                return err
        }

        // Set the client token to the API client
        vaultClient.SetToken(secret.Auth.ClientToken)
        return nil
}

// ClientFactoryAWSEC2Auth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained by
// authenticating against Vault via its AWS EC2 endpoint.
type ClientFactoryAWSEC2Auth struct {
	// (Required) role is the Vault role associated with the
        // IAM role used in the sts:GetCallerIdentity request. This
        // Vault role should have permission to read the secret
        // specified in your config.json file.
	role string
}

func NewClientFactoryAWSEC2Auth(role string) ClientFactory {
	return &ClientFactoryAWSEC2Auth{role}
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

        // Get the EC2 instance's PKCS7 signature and login to
        // Vault to obtain a token via Vault's AWS EC2 endpoint
        if err = c.getAndSetToken(vaultClient); err != nil {
                return nil, err
        }

        return NewDefaultClient(vaultClient), nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS EC2
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient 
// object.
func (c *ClientFactoryAWSEC2Auth) WithClient(vaultClient *api.Client) (Client, error) {
        // Get the EC2 instance's PKCS7 signature and login to
        // Vault to obtain a token via Vault's AWS EC2 endpoint
        if err := c.getAndSetToken(vaultClient); err != nil {
                return nil, err
        }

        return NewDefaultClient(vaultClient), nil
}

func (c *ClientFactoryAWSEC2Auth) getAndSetToken(vaultClient *api.Client) error {
	// Create a new AWS client
        awsClient, err := aws.NewDefaultClient()
        if err != nil {
                return err
        }

	// Get the elements of the EC2 metadata required to
	// authenticate against Vault
        pkcs7, err := awsClient.GetPKCS7Signature()
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
        return nil
}

// ClientFactoryTokenAuth is used to either create a new Vault
// API client with a valid Vault token or to give an existing
// Vault API client a valid token. The token is obtained from
// the VAULT_TOKEN environment variable.
type ClientFactoryTokenAuth struct {}

func NewClientFactoryTokenAuth() ClientFactory {
        return &ClientFactoryTokenAuth{}
}

// NewClient creates a new Vault API client. It expects the various Vault
// environment variables to be set as necessary (e.g. VAULT_TOKEN,
// VAULT_ADDR, etc.). If the VAULT_TOKEN environment variable is not set,
// NewClient will return an error. Otherwise, it will return a 
// DefaultClient object.
func (c *ClientFactoryTokenAuth) NewClient() (Client, error) {
        // Create a new Vault API client
        client, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }

        // Check if the Vault API client has a token.
        // If not, raise an error.
        if v := client.Token(); v == "" {
                return nil, fmt.Errorf("%s %s %s",
                        "Vault API client has no token. Make sure to set the token using the", 
                        api.EnvVaultToken, "environment variable")
        }

        return NewDefaultClient(client), nil
}

// WithClient retrieves the environment variable set by the VAULT_TOKEN
// environment variable and sets the Vault API client with this token
// and returns a DefaultClient object. Note that this will overwrite 
// the client's existing token if it has one.
func (c *ClientFactoryTokenAuth) WithClient(client *api.Client) (Client, error) {
        if v := os.Getenv(api.EnvVaultToken); v != "" {
                client.SetToken(v)
        } else {
                return nil, fmt.Errorf("%s environment variable is not set", api.EnvVaultToken)
        }

        return NewDefaultClient(client), nil
}
