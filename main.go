package main

import (
        "fmt"
        "flag"
        "log"
        "os"

        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/helper"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/config"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/version"
)

func main() {
        var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.Parse()

	// Exit safely when version is used
	if versionFlag {
		fmt.Println(version.Version)
		os.Exit(0)
        }

        cfg, err := config.GetCredHelperConfig()
        if err != nil {
                log.Fatalf("Error parsing configuration file: %+v", err)
        }

        client, err := vault.NewClient(cfg.Method, cfg.Role, cfg.ServerID)
        if err != nil {
                log.Fatalf("Error initializing Vault client: %+v", err)
        }

        credentials.Serve(helper.NewHelper(cfg.Secret, client))
}
