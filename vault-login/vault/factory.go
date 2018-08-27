package vault

import (
        "fmt"
        "encoding/base64"
        "encoding/json"
        "os"
        "path"

        "github.com/hashicorp/vault/api"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/aws"
)

type ClientFactory interface {
        WithClient(*api.Client) (Client, error)
        NewClient() (Client, error)
}

type ClientFactoryAWSAuth struct {
        role     string
        serverID string
}

func NewClientFactoryAWSAuth(role, serverID string) ClientFactory {
        return &ClientFactoryAWSAuth{
                role:     role,
                serverID: serverID,
        }
}

// NewClient creates a new Vault API client and uses it to attempt to
// authenticate against Vault via the AWS IAM endpoint. If authentication
// is successful, it will set the Vault API client with the newly-created
// client token and return a DefaultClient object.
func (c *ClientFactoryAWSAuth) NewClient() (Client, error) {
        // Create a new Vault API client
        client, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }

        if err = c.getAndSetToken(client); err != nil {
                return nil, err
        }

        return NewDefaultClient(client), nil
}

// WithClient receives a Vault API client that has already been initialized
// and uses it to attempt to authenticate against Vault via the AWS IAM
// endpoint. If authentication is successful, it will set the Vault API
// client with the newly-created client token and return a DefaultClient 
// object.
func (c *ClientFactoryAWSAuth) WithClient(client *api.Client) (Client, error) {
        if err := c.getAndSetToken(client); err != nil {
                return nil, err
        }

        return NewDefaultClient(client), nil
}

// getAndSetToken creates an AWS sts:GetCallerIdentity request, gets the
// request elements required to authenticate against the Vault AWS IAM auth
// endpoint, makes the authentication request to Vault, and if successful it
// sets the token of Vault API client with the newly-created Vault token. 
func (c *ClientFactoryAWSAuth) getAndSetToken(client *api.Client) error {
        // Create an AWS client
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
        buf, err := json.Marshal(elems.Headers)
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
        secret, err := client.Logical().Write(path.Join("auth", "aws", "login"), payload)
        if err != nil {
                return err
        }

        // Set the client token to the API client
        client.SetToken(secret.Auth.ClientToken)
        return nil
}

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
