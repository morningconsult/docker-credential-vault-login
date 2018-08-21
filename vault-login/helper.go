package helper

import (
        "fmt"

        log "github.com/cihub/seelog"
        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/config"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/vault"
)

var notImplementedError = fmt.Errorf("not implemented")

type Helper struct {}

func NewHelper() Helper {
        return Helper{}
}

func (h Helper) Add(creds *credentials.Credentials) error {
        return notImplementedError
}

func (h Helper) Delete(serverURL string) error {
        return notImplementedError
}

func (h Helper) Get(serverURL string) (string, string, error) {
        var factory vault.ClientFactory

        // Parse the config.json file
        cfg, err := config.GetCredHelperConfig()
        if err != nil {
                log.Errorf("Error parsing configuration file: %v")
                return "", "", credentials.NewErrCredentialsNotFound()
        }

        // Create a Vault API client factory based on the type of
        // authentication method specified in the config file
        switch cfg.Method {
        case config.VaultAuthMethodAWS:
                factory = vault.NewClientFactoryAWSAuth(cfg.Role, cfg.ServerID)
        case config.VaultAuthMethodToken:
                factory = vault.NewClientFactoryTokenAuth()
        default:
                log.Errorf("Unknown authentication method: %q", cfg.Method)
                return "", "", credentials.NewErrCredentialsNotFound()
        }

        client, err := factory.NewClient()
        if err != nil {
                log.Errorf("Error creating a new Vault client: %v", err)
                return "", "", credentials.NewErrCredentialsNotFound()
        }

        // Get the Docker credentials from Vault
        creds, err := client.GetCredentials(cfg.Secret)
        if err != nil {
                log.Errorf("Error getting Docker credentials from Vault: %v", err)
                return "", "", credentials.NewErrCredentialsNotFound()
        }

        return creds.Username, creds.Password, nil
}

func (h Helper) List() (map[string]string, error) {
        // might be good to store secrets like
        // "dockerServerURL" : {
        //        "username": "foo"
        //        "password": "bar"
        // }"
        return nil, notImplementedError
}
