package main

import (
        "log"

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

        // cfg.Validate() ?

        client, err := vault.NewClient(cfg.Method, cfg.Role, cfg.ServerID)
        if err != nil {
                log.Fatalf("Error initializing Vault client: %+v", err)
        }

        credentials.Serve(helper.NewHelper(cfg.Secret, client))
}
