package main

import (
        "log"

        "github.com/hashicorp/vault/api"
        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/helper"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/config"
)

func main() {
        cfg, err := config.GetCredHelperConfig()
        if err != nil {
                log.Fatalf("Error parsing configuration file: %+v", err)
        }

        if cfg.Method == config.VaultAuthMethodAWS {
                err := vault.GetAndSetToken(cfg.Role, cfg.ServerID)
                if err != nil {
                        log.Fatalf("Error making HTTP request to Vault's AWS IAM login endpoint: %+v", err)
                }
        }

        client, err := api.NewClient(nil)
        if err != nil {
                log.Fatalf("Error initializing Vault client: %+v\n", err)
        }

        credentials.Serve(helper.NewHelper(cfg.Path, client))
}
