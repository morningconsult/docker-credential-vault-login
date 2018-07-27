package main

import (
        "log"
        "os"
        
        vault "github.com/hashicorp/vault/api"
        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/helper"
)

const (
        // EnvDockerCredsVaultPath is the path in Vault where the Docker
        // login credentials are stored
        EnvDockerCredsVaultPath string = "DOCKER_CREDS_VAULT_PATH"
)

func main() {
        var secretPath string

        if secretPath = os.Getenv(EnvDockerCredsVaultPath); secretPath == "" {
                log.Fatalf("Environment variable %s is not set\n", EnvDockerCredsVaultPath)
        }

        client, err := vault.NewClient(nil)
        if err != nil {
                log.Fatalf("Error initializing Vault client: %+v\n", err)
        }

        credentials.Serve(helper.NewHelper(secretPath, client))
}
