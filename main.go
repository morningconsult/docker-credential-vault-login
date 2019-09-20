// Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/command/agent/config"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/xerrors"

	"github.com/morningconsult/docker-credential-vault-login/helper"
	"github.com/morningconsult/docker-credential-vault-login/vault"
	"github.com/morningconsult/docker-credential-vault-login/version"
)

const (
	banner = "Docker Credential Helper for Vault Storage version %v, commit %v, built %v\n"

	defaultConfigFile = "/etc/docker-credential-vault-login/config.hcl"
	defaultLogDir     = "~/.docker-credential-vault-login"

	envConfigFile     = "DCVL_CONFIG_FILE"
	envLogDir         = "DCVL_LOG_DIR"
	envSecretPath     = "DCVL_SECRET"
	envDisableCaching = "DCVL_DISABLE_CACHE"
)

func main() {
	var versionFlag, disableCache bool
	var configFile string
	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.BoolVar(&disableCache, "disable-cache", false, "disable token caching")
	flag.StringVar(&configFile, "config", defaultConfigFile, "path to the configuration file")
	flag.Parse()

	// Exit safely when version is used
	if versionFlag {
		fmt.Printf(banner, version.Version, version.Commit, version.Date)
		os.Exit(0)
	}

	// Parse config file
	config, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("error parsing configuration file: %v", err)
	}

	// Get the path to where the secret is kept in Vault
	secretPath, err := getSecretPath(config.AutoAuth.Method.Config)
	if err != nil {
		log.Fatalf("error getting path to secret: %v", err)
	}

	// Create new Vault client
	client, err := vault.NewClient(config.Vault)
	if err != nil {
		log.Fatalf("error creating new Vault client: %v", err)
	}

	// Check whether caching should be enabled
	enableCache, err := cacheEnabled(disableCache)
	if err != nil {
		log.Fatal(err)
	}

	// Open log writer
	logWriter, err := newLogWriter(config.AutoAuth.Method.Config)
	if err != nil {
		log.Fatalf("error creating log file: %v", err)
	}
	defer logWriter.Close()

	// Create logger
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Error,
		Output: logWriter,
	})

	authMethod, err := vault.BuildAuthMethod(config.AutoAuth.Method, logger)
	if err != nil {
		logWriter.Close()
		log.Fatalf("error creating auth method: %v", err)
	}

	sinks, err := vault.BuildSinks(config.AutoAuth.Sinks, logger, client)
	if err != nil {
		logWriter.Close()
		log.Fatalf("error creating sink(s): %v", err)
	}

	// Create a new credential helper
	helper := helper.New(helper.Options{
		Logger:      logger,
		Client:      client,
		Secret:      secretPath,
		EnableCache: enableCache,
		WrapTTL:     config.AutoAuth.Method.WrapTTL,
		AuthMethod:  authMethod,
		Sinks:       sinks,
	})
	credentials.Serve(helper)
}

func loadConfig(configFile string) (*config.Config, error) {
	// Get path to config file
	if f := os.Getenv(envConfigFile); f != "" {
		var err error
		configFile, err = homedir.Expand(f)
		if err != nil {
			return nil, xerrors.Errorf("error expanding directory %q: %w", f, err)
		}
	}

	// Parse config file
	config, err := config.LoadConfig(configFile, nil)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, xerrors.New("no configuration read. Please provide the configuration file with the " +
			envConfigFile + " environment variable.")
	}
	if config.AutoAuth == nil {
		return nil, xerrors.New("no 'auto_auth' block found in configuration file")
	}
	if config.AutoAuth.Method == nil {
		return nil, xerrors.New("no 'auto_auth.method' block found in configuration file")
	}
	return config, nil
}

func getSecretPath(config map[string]interface{}) (string, error) {
	secret := os.Getenv(envSecretPath)
	if secret == "" {
		secretRaw, ok := config["secret"]
		if !ok {
			return "", xerrors.Errorf("The path to the secret where your Docker credentials are "+
				"stored must be specified via either (1) the %s environment variable or (2) the "+
				"field 'auto_auth.config.secret' of the config file.", envSecretPath)
		}
		secret, ok = secretRaw.(string)
		if !ok {
			return "", xerrors.Errorf("field 'auto_auth.method.config.secret' could not be converted to string")
		}
	}
	return secret, nil
}

func newLogWriter(config map[string]interface{}) (*os.File, error) {
	logDir := defaultLogDir
	if v := os.Getenv(envLogDir); v != "" {
		logDir = v
	} else {
		l, ok := config["log_dir"].(string)
		if ok && l != "" {
			logDir = v
		}
	}
	logDir, err := homedir.Expand(logDir)
	if err != nil {
		return nil, xerrors.Errorf("error expanding logging directory %s: %w", logDir, err)
	}
	if err = os.MkdirAll(logDir, 0755); err != nil {
		return nil, xerrors.Errorf("error creating directory %s: %w", logDir, err)
	}
	logFile := filepath.Join(logDir, fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))
	return os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func cacheEnabled(disableCache bool) (bool, error) {
	if v := os.Getenv(envDisableCaching); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, xerrors.Errorf("value of %s could not be converted to boolean", envDisableCaching)
		}
		disableCache = b
	}
	return !disableCache, nil
}
