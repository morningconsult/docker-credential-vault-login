// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//         https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"flag"
	"fmt"
	"os"

	log "github.com/cihub/seelog"
	"github.com/docker/docker-credential-helpers/credentials"
	vault "github.com/morningconsult/docker-credential-vault-login/vault-login"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/cache/logging"
	"github.com/morningconsult/docker-credential-vault-login/vault-login/version"
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

	cacheUtil := cache.NewCacheUtil(nil)

	defer log.Flush()
	logging.SetupLogger(cacheUtil.GetCacheDir())

	// Create a new vault.Helper instance
	helper, err := vault.NewHelper(&vault.HelperOptions{CacheUtil: cacheUtil})
	if err != nil {
		log.Errorf("error creating new vault.Helper instance: %v", err)
		os.Exit(1)
	}

	credentials.Serve(helper)
}
