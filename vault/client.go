package vault

import (
        "fmt"
        "encoding/base64"
        "encoding/json"
        "path"

        "github.com/hashicorp/vault/api"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/aws"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/config"
)

func NewClient(method config.VaultAuthMethod, role, serverID string) (*api.Client, error) {
        client, err := api.NewClient(nil)
        if err != nil {
                return nil, err
        }
        if method == config.VaultAuthMethodAWS {
                // If this is the case, then presumably the client has no token.
                if err = getAndSetToken(client, role, serverID); err != nil {
                        return nil, err
                }
        }
        return client, nil
}

func getAndSetToken(client *api.Client, role, serverID string) error {
        // Create parameters for an sts:GetCallerIdentity request
        elems, err := aws.GetIAMAuthElements(serverID)
        if err != nil {
                return fmt.Errorf("error building sts:GetCallerIdentity request: %v", err)
        }

        // Build the request payload
        payload, err := makePayload(role, elems)
        if err != nil {
                return fmt.Errorf("error creating Vault AWS login request payload: %v", err)
        }

        secret, err := client.Logical().Write(path.Join("auth", "aws", "login"), payload)
        if err != nil {
                return fmt.Errorf("error making Vault AWS login request: %v", err)
        }

        client.SetToken(secret.Auth.ClientToken)
        return nil
}

func makePayload(role string, elems *aws.IAMAuthElements) (map[string]interface{}, error) {
        buf, err := json.Marshal(elems.Headers)
        if err != nil {
                return nil, err
        }
        headers := base64.StdEncoding.EncodeToString(buf)
        url := base64.StdEncoding.EncodeToString([]byte(elems.URL))
        body := base64.StdEncoding.EncodeToString(elems.Body)

        return map[string]interface{}{
                "role":                    role,
                "iam_http_request_method": elems.Method,
                "iam_request_url":         url,
                "iam_request_body":        body,
                "iam_request_headers":     headers,
        }, nil
}