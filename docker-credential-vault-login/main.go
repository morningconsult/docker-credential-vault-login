package main

import (
        "fmt"
        "flag"
        "log"
        "os"

        log "github.com/cihub/seelog"
        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault/helper"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/docker-credential-vault-login/logging"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/docker-credential-vault-login/version"
)

const banner = "Docker Credential Helper for Vault Storage v%s ('%s')\n"

func main() {
        var versionFlag bool
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.Parse()

	// Exit safely when version is used
	if versionFlag {
		fmt.Printf(banner, version.Version, version.GitCommitSHA)
		os.Exit(0)
        }

        defer log.Flush()
        logging.SetupLogger()

        // cfg, err := config.GetCredHelperConfig()
        // if err != nil {
        //         log.Fatalf("Error parsing configuration file: %+v", err)
        // }

        // client, err := vault.NewClient(cfg.Method, cfg.Role, cfg.ServerID)
        // if err != nil {
        //         log.Fatalf("Error initializing Vault client: %+v", err)
        // }

        credentials.Serve(helper.NewHelper(cfg.Secret, client))
}
