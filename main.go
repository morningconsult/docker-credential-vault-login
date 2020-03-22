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
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaultConfig "github.com/hashicorp/vault/command/agent/config"
	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/xerrors"

	"github.com/morningconsult/docker-credential-vault-login/config"
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
	envDisableCaching = "DCVL_DISABLE_CACHE"
)

func main() { // nolint: funlen
	var (
		versionFlag, disableCache bool
		configFile                string
	)

	flag.BoolVar(&versionFlag, "version", false, "print version and exit")
	flag.BoolVar(&disableCache, "disable-cache", false, "disable token caching")
	flag.StringVar(&configFile, "config", defaultConfigFile, "path to the configuration file")
	flag.Parse()

	// Exit safely when version is used
	if versionFlag {
		fmt.Printf(banner, version.Version, version.Commit, version.Date)
		os.Exit(0)
	}

	// Get path to config file
	if f := os.Getenv(envConfigFile); f != "" {
		var err error

		configFile, err = homedir.Expand(f)
		if err != nil {
			log.Fatalf("error expanding directory %q: %v", f, err)
		}
	}

	// Parse config file
	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatalf("error parsing configuration file: %v", err)
	}

	// Get a Vault token (if using the 'token' auth method)
	token, err := getToken(cfg.AutoAuth.Method)
	if err != nil {
		log.Fatalf("error getting Vault token: %v", err)
	}

	// Build secrets table
	secretsTable, err := config.BuildSecretsTable(cfg.AutoAuth.Method.Config)
	if err != nil {
		log.Fatalf("error building secrets table: %v", err)
	}

	// Create new Vault client
	vaultClient, err := newVaultClient(cfg.Vault)
	if err != nil {
		log.Fatalf("error creating new Vault client: %v", err)
	}

	// Check whether caching should be enabled
	enableCache, err := cacheEnabled(disableCache)
	if err != nil {
		log.Fatal(err)
	}

	// Open log writer
	logWriter, err := newLogWriter(cfg.AutoAuth.Method.Config)
	if err != nil {
		log.Fatalf("error creating log file: %v", err)
	}
	defer logWriter.Close()

	// Create logger
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Error,
		Output: logWriter,
	})

	// Create a wrapped Vault client
	client := vault.NewClient(vault.ClientOptions{
		Logger:     logger.Named("vault.client"),
		Client:     vaultClient,
		AuthConfig: cfg.AutoAuth,
	})

	// Create a new credential helper
	helper := helper.New(helper.Options{
		Logger:      logger.Named("helper"),
		Client:      client,
		Secret:      secretsTable,
		EnableCache: enableCache,
		Token:       token,
	})
	credentials.Serve(helper)
}

func newLogWriter(config map[string]interface{}) (*os.File, error) {
	logDir := defaultLogDir
	if v := os.Getenv(envLogDir); v != "" {
		logDir = v
	} else {
		l, ok := config["log_dir"].(string)
		if ok && l != "" {
			logDir = l
		}
	}

	logDir, err := homedir.Expand(logDir)
	if err != nil {
		return nil, xerrors.Errorf("error expanding logging directory %s: %w", logDir, err)
	}

	if err = os.MkdirAll(logDir, 0750); err != nil {
		return nil, xerrors.Errorf("error creating directory %s: %w", logDir, err)
	}

	logFile := filepath.Join(logDir, fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))

	return os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
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

func getToken(method *vaultConfig.Method) (string, error) {
	token := ""

	if method.Type == "token" {
		tokenRaw, ok := method.Config["token"]
		if !ok {
			return "", errors.New("missing 'auto_auth.method.config.token' value")
		}

		token, ok = tokenRaw.(string)
		if !ok {
			return "", errors.New("could not convert 'auto_auth.method.config.token' config value to string")
		}

		if token == "" {
			return "", errors.New("'auto_auth.method.config.token' value is empty")
		}
	}

	return token, nil
}

func newVaultClient(cfg *vaultConfig.Vault) (*api.Client, error) { // nolint: gocognit, gocyclo
	if cfg != nil {
		if os.Getenv(api.EnvVaultAddress) == "" && cfg.Address != "" {
			os.Setenv(api.EnvVaultAddress, cfg.Address)
			defer os.Unsetenv(api.EnvVaultAddress)
		}

		if os.Getenv(api.EnvVaultCACert) == "" && cfg.CACert != "" {
			os.Setenv(api.EnvVaultCACert, cfg.CACert)
			defer os.Unsetenv(api.EnvVaultCACert)
		}

		if os.Getenv(api.EnvVaultCAPath) == "" && cfg.CAPath != "" {
			os.Setenv(api.EnvVaultCAPath, cfg.CAPath)
			defer os.Unsetenv(api.EnvVaultCAPath)
		}

		if os.Getenv(api.EnvVaultSkipVerify) == "" && cfg.TLSSkipVerifyRaw != nil {
			os.Setenv(api.EnvVaultSkipVerify, fmt.Sprintf("%t", cfg.TLSSkipVerify))
			defer os.Unsetenv(api.EnvVaultSkipVerify)
		}

		if os.Getenv(api.EnvVaultClientCert) == "" && cfg.ClientCert != "" {
			os.Setenv(api.EnvVaultClientCert, cfg.ClientCert)
			defer os.Unsetenv(api.EnvVaultClientCert)
		}

		if os.Getenv(api.EnvVaultClientKey) == "" && cfg.ClientKey != "" {
			os.Setenv(api.EnvVaultClientKey, cfg.ClientKey)
			defer os.Unsetenv(api.EnvVaultClientKey)
		}
	}

	clientConfig := api.DefaultConfig()
	if clientConfig.Error != nil {
		return nil, clientConfig.Error
	}

	client, err := api.NewClient(clientConfig)
	if err != nil {
		return nil, err
	}

	client.ClearToken()

	return client, nil
}
