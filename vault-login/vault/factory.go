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

func (c *ClientFactoryAWSAuth) NewClient() (Client, error) {
        // Create a new Vault API client
        client, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }

        // Create an AWS client
        awsClient, err := aws.NewDefaultClient()
        if err != nil {
                return nil, err
        }

        // Create an sts:GetCallerIdentity request and return the elements
        // of the request needed for Vault to authenticate against IAM
        elems, err := awsClient.GetIAMAuthElements(c.serverID)
        if err != nil {
                return nil, err
        }

        // Build the request payload
        buf, err := json.Marshal(elems.Headers)
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
        secret, err := client.Logical().Write(path.Join("auth", "aws", "login"), payload)
        if err != nil {
                return nil, err
        }

        // Set the client token to the API client
        client.SetToken(secret.Auth.ClientToken)

        return NewDefaultClient(client), nil
}

type ClientFactoryTokenAuth struct {}

func NewClientFactoryTokenAuth() ClientFactory {
        return &ClientFactoryTokenAuth{}
}

func (c *ClientFactoryTokenAuth) NewClient() (Client, error) {
        // Create a new Vault API client
        client, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }

        // Check if the Vault API client has a token.
        // If not, raise an error.
        if v := client.Token(); v == "" {
                return nil, fmt.Errorf("%s %s",
                        "Vault API client has no token.",
                        "Make sure to set the token using the VAULT_TOKEN environment variable.")
        }

        return NewDefaultClient(client), nil
}
