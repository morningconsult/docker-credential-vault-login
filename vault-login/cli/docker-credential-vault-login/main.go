package main

import (
        "fmt"
        "flag"
        "os"

        log "github.com/cihub/seelog"
        "github.com/docker/docker-credential-helpers/credentials"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/helper"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/logging"
        "gitlab.morningconsult.com/mci/docker-credential-vault-login/vault-login/version"
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
        
        credentials.Serve(helper.NewHelper(nil))
}
