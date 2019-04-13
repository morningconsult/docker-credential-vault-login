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

package helper

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
)

func TestNewHelper(t *testing.T) {
	h := NewHelper(&HelperOptions{
		AuthTimeout: 1,
	})

	if h.authTimeout != time.Duration(1)*time.Second {
		t.Fatal("Helper.authDuration != 1")
	}
}

func TestHelper_Add(t *testing.T) {
	h := NewHelper(nil)
	err := h.Add(&credentials.Credentials{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_Delete(t *testing.T) {
	h := NewHelper(nil)
	err := h.Delete("")
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_List(t *testing.T) {
	h := NewHelper(nil)
	_, err := h.List()
	if err == nil {
		t.Fatal("expected an error")
	}
	if err.Error() != "not implemented" {
		t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), "not implemented"))
	}
}

func TestHelper_Get_config(t *testing.T) {
	config := os.Getenv(EnvConfigFile)
	defer os.Setenv(EnvConfigFile, config)
	os.Setenv(EnvConfigFile, "testdata/empty-file.hcl")

	h := NewHelper(nil)

	_, _, err := h.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestHelper_Get_newVaultClient(t *testing.T) {
	oldConfig := os.Getenv(EnvConfigFile)
	defer os.Setenv(EnvConfigFile, oldConfig)
	os.Setenv(EnvConfigFile, "testdata/valid.hcl")

	oldLog := os.Getenv("DCVL_LOG_DIR")
	defer os.Setenv("DCVL_LOG_DIR", oldLog)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("DCVL_LOG_DIR", testdata)

	oldRL := os.Getenv(api.EnvRateLimit)
	defer os.Setenv(api.EnvRateLimit, oldRL)
	os.Setenv(api.EnvRateLimit, "not an int!") // Causes newVaultClient() to return an error

	h := NewHelper(nil)

	_, _, err = h.Get("")
	if err == nil {
		t.Fatal(err)
	}

	logfile := filepath.Join(testdata, fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))

	if _, err := os.Stat(logfile); os.IsNotExist(err) {
		t.Fatalf("log file %s was not created", logfile)
	}
	defer os.Remove(logfile)

	data, err := ioutil.ReadFile(logfile)
	if err != nil {
		t.Fatal(err)
	}

	expected := `[ERROR] helper.get: error creating new Vault API client: error="error encountered setting up default configuration: VAULT_RATE_LIMIT was provided but incorrectly formatted"`
	if !strings.Contains(string(data), expected) {
		t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, string(data))
	}
}

func TestHelper_Get(t *testing.T) {

	logdir := os.Getenv("DCVL_LOG_DIR")
	defer os.Setenv("DCVL_LOG_DIR", logdir)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("DCVL_LOG_DIR", testdata)
	defer os.Remove(filepath.Join(testdata, fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02"))))

	coreConfig := &vault.CoreConfig{
		Logger: logging.NewVaultLogger(hclog.Error),
		CredentialBackends: map[string]logical.Factory{
			"approle": approle.Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	core := cluster.Cores[0].Core
	vault.TestWaitActive(t, core)
	client := cluster.Cores[0].Client
	rootToken := client.Token()

	// Mount the auth backend
	err = client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{
		Type: "approle",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Tune the mount
	err = client.Sys().TuneMount("auth/approle", api.MountConfigInput{
		DefaultLeaseTTL: "20s",
		MaxLeaseTTL:     "20s",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create role
	resp, err := client.Logical().Write("auth/approle/role/role-period", map[string]interface{}{
		"period":   "20s",
		"policies": "dev-policy",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Get role_id
	resp, err = client.Logical().Read("auth/approle/role/role-period/role-id")
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the role-id")
	}
	roleID, ok := resp.Data["role_id"].(string)
	if !ok {
		t.Fatal("could not convert 'role_id' to string")
	}
	roleIDFile := filepath.Join(testdata, "test-approle-role-id")
	defer os.Remove(roleIDFile)

	// Get secret_id
	resp, err = client.Logical().Write("auth/approle/role/role-period/secret-id", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected a response for fetching the secret-id")
	}
	secretID, ok := resp.Data["secret_id"].(string)
	if !ok {
		t.Fatal("could not convert 'secret_id' to string")
	}
	secretIDFile := filepath.Join(testdata, "test-approle-secret-id")
	defer os.Remove(secretIDFile)

	makeApproleFiles := func() {
		if err := ioutil.WriteFile(secretIDFile, []byte(secretID), 0644); err != nil {
			t.Fatal(err)
		}
		if err := ioutil.WriteFile(roleIDFile, []byte(roleID), 0644); err != nil {
			t.Fatal(err)
		}
	}

	makeApproleFiles()

	// Write a secret
	_, err = client.Logical().Write("secret/docker/creds", map[string]interface{}{
		"username": "test@user.com",
		"password": "secure password",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Give the approle permission to read the secret
	policy := `path "secret/docker/creds" {
	capabilities = ["read", "list"]
}`
	if err = client.Sys().PutPolicy("dev-policy", policy); err != nil {
		t.Fatal(err)
	}

	hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			secret              = "secret/docker/creds"
			role_id_file_path   = %q
			secret_id_file_path = %q
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
	hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)

	configFile := filepath.Join(testdata, "testing.hcl")
	if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(configFile)
	defer os.Remove("testdata/token-sink")

	oldConfig := os.Getenv(EnvConfigFile)
	defer os.Setenv(EnvConfigFile, oldConfig)
	os.Setenv(EnvConfigFile, configFile)

	client.ClearToken()

	h := NewHelper(&HelperOptions{
		Client:      client,
		AuthTimeout: 3,
	})

	// Test that it can read authenticate, get a new token, and read the secret
	user, pw, err := h.Get("")
	if err != nil {
		t.Fatal(err)
	}

	if user != "test@user.com" {
		t.Fatalf("Got username %q, expected \"test@user.com\"", user)
	}
	if pw != "secure password" {
		t.Fatalf("Got password %q, expected \"secure password\"", pw)
	}

	if _, err = os.Stat("testdata/token-sink"); err != nil {
		t.Fatal(err)
	}

	data, err := ioutil.ReadFile("testdata/token-sink")
	if err != nil {
		t.Fatal(err)
	}
	clientToken := string(data)

	// Test that it can read the secret using the cached token
	t.Run("can-use-cached-token", func(t *testing.T) {
		h.client.ClearToken()
		h.logger = nil

		makeApproleFiles()

		user, pw, err := h.Get("")
		if err != nil {
			t.Fatal(err)
		}

		if user != "test@user.com" {
			t.Fatalf("Got username %q, expected \"test@user.com\"", user)
		}
		if pw != "secure password" {
			t.Fatalf("Got password %q, expected \"secure password\"", pw)
		}
	})

	// Test that caching can be disabled by setting the environment
	// variable
	t.Run("can-disable-caching", func(t *testing.T) {
		h.client.ClearToken()
		h.logger = nil

		makeApproleFiles()

		os.Setenv(EnvDisableCaching, "true")
		defer os.Unsetenv(EnvDisableCaching)

		os.Remove("testdata/token-sink")
		user, pw, err := h.Get("")
		if err != nil {
			t.Fatal(err)
		}

		if user != "test@user.com" {
			t.Fatalf("Got username %q, expected \"test@user.com\"", user)
		}
		if pw != "secure password" {
			t.Fatalf("Got password %q, expected \"secure password\"", pw)
		}
		if _, err = os.Stat("testdata/token-sink"); !os.IsNotExist(err) {
			t.Fatal("helper.Get() should not have cached a token")
		}
	})

	// Test that if the environment variable used to disable caching
	// will cause strconv.ParseBool() to return an error when the value
	// is not a bool
	t.Run("disable-caching-error", func(t *testing.T) {
		buf := new(bytes.Buffer)
		h.client.ClearToken()
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		makeApproleFiles()

		os.Setenv(EnvDisableCaching, "Not a boolean :(")
		defer os.Unsetenv(EnvDisableCaching)

		oldConfig := os.Getenv(EnvConfigFile)
		defer os.Setenv(EnvConfigFile, oldConfig)
		os.Setenv(EnvConfigFile, "testdata/valid.hcl")

		_, _, err := h.Get("")
		if err == nil {
			t.Fatal("Expected an error")
		}

		expected := `[ERROR] Value of DCVL_DISABLE_CACHE could not be converted to boolean. Defaulting to false.`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("\nExpected error to contain:\n\t%s\nReceived the following error(s):\n\t%s",
				expected, buf.String())
		}
	})

	// Ensure that if the client attempts to read the secret with
	// a bad token it fails
	t.Run("fails-when-bad-token-used", func(t *testing.T) {
		h.client.SetToken("bad token!")
		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		makeApproleFiles()

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error when client attempts to read secret with a bad token")
		}
		expected := fmt.Sprintf(`[ERROR] error reading secret from Vault: error="error reading secret: Error making API request.

URL: GET %s/v1/secret/docker/creds
Code: 403. Errors:

* permission denied"`, h.client.Address())
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("\nExpected error to contain:\n\t%s\nReceived the following error(s):\n\t%s",
				expected, buf.String())
		}
	})

	// Ensure that if the role does not have permission to read
	// the secret, it fails
	t.Run("fails-when-no-policy", func(t *testing.T) {
		client.SetToken(rootToken)
		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
			Level:  hclog.Error,
		})

		if err = client.Sys().DeletePolicy("dev-policy"); err != nil {
			t.Fatal(err)
		}

		h.client.SetToken(clientToken)
		makeApproleFiles()

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error when role attempts to read secret with without permission")
		}

		expected := fmt.Sprintf(`[ERROR] error reading secret from Vault: error="error reading secret: Error making API request.

URL: GET %s/v1/secret/docker/creds
Code: 403. Errors:

* 1 error occurred:
	* permission denied`, h.client.Address())
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("\nExpected error to contain:\n\t%s\nReceived the following error(s):\n\t%s",
				expected, buf.String())
		}
	})

	// Tests that buildSinks() returns an error when a sink specified in
	// the config file is not a supported type
	t.Run("build-sinks-error", func(t *testing.T) {
		hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			secret              = "secret/docker/creds"
			role_id_file_path   = %q
			secret_id_file_path = %q
		}
	}

	sink "kitchen" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
		hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)
		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}

		os.Remove("testdata/token-sink")

		h.client.ClearToken()

		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		makeApproleFiles()

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `[ERROR] error building sinks: error="unknown sink type "kitchen""`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

	// Tests that buildMethod() returns an error when the method specified
	// in the config file is not supported
	t.Run("build-method-error", func(t *testing.T) {
		hcl := `auto_auth {
	method "retina" {
		mount_path = "auth/approle"
		config     = {
			secret = "secret/docker/creds"
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`

		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}

		os.Remove("testdata/token-sink")

		h.client.ClearToken()

		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `[ERROR] error building method: error="unknown auth method "retina""`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

	// Tests that parseConfig() returns an error when there is no secret
	// in the config file
	t.Run("no-secret", func(t *testing.T) {
		hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			role_id_file_path   = %q
			secret_id_file_path = %q
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
		hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)
		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}
		os.Remove("testdata/token-sink")

		h.client.ClearToken()

		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `[ERROR] The path to the secret where your Docker credentials are stored must be specified via either (1) the DCVL_SECRET environment variable or (2) the field 'auto_auth.config.secret' of the config file.`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

	t.Run("can-set-logger-in-config", func(t *testing.T) {
		hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			// no secret provided so execution stops quickly after creating the logger
			role_id_file_path   = %q
			secret_id_file_path = %q
			log_dir             = "testdata"
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
		logFile := fmt.Sprintf("testdata/vault-login_%s.log", time.Now().Format("2006-01-02"))
		os.Remove(logFile)
		defer os.Remove(logFile)

		hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)
		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}

		h.client.ClearToken()
		h.logger = nil

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		if _, err = os.Stat(logFile); os.IsNotExist(err) {
			t.Fatalf("should have created a new log file, but didn't")
		}
	})

	t.Run("fails-when-no-write-permissions", func(t *testing.T) {
		hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			// no secret provided so execution stops quickly after creating the logger
			role_id_file_path   = %q
			secret_id_file_path = %q
			log_dir             = "testdata/logs"
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
		logDir := os.Getenv("DCVL_LOG_DIR")
		defer os.Setenv("DCVL_LOG_DIR", logDir)
		os.Unsetenv("DCVL_LOG_DIR")

		oldConfig := os.Getenv(EnvConfigFile)
		defer os.Setenv(EnvConfigFile, oldConfig)
		os.Setenv(EnvConfigFile, configFile)

		buf := new(bytes.Buffer)
		log.SetOutput(buf)
		defer log.SetOutput(os.Stdout)

		hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)
		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}

		if err = os.Mkdir("testdata/logs", 0444); err != nil {
			t.Fatal(err)
		}
		defer func() {
			files, err := filepath.Glob("testdata/logs/*")
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				os.Remove(file)
			}
			os.Remove("testdata/logs")
		}()

		h.client.ClearToken()
		h.logger = nil

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `error opening log file (logging errors to stderr instead): error opening/creating log file testdata/logs/vault-login`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

	// Tests that parseConfig() returns an error when the secret is not a string
	t.Run("secret-not-string", func(t *testing.T) {
		hcl := `auto_auth {
	method "approle" {
		mount_path = "auth/approle"
		config     = {
			secret              = 1234
			role_id_file_path   = %q
			secret_id_file_path = %q
		}
	}

	sink "file" {
		config = {
			path = "testdata/token-sink"
		}
	}
}`
		hcl = fmt.Sprintf(hcl, roleIDFile, secretIDFile)
		if err = ioutil.WriteFile(configFile, []byte(hcl), 0644); err != nil {
			t.Fatal(err)
		}
		os.Remove("testdata/token-sink")

		h.client.ClearToken()

		buf := new(bytes.Buffer)
		h.logger = hclog.New(&hclog.LoggerOptions{
			Output: buf,
		})

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `[ERROR] field 'auto_auth.method.config.secret' could not be converted to string`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

	// Test that if the value of DCVL_CONFIG_FILE cannot be expanded by
	// github.com/mitchellh/go-homedir.Expand(), then the appropriate
	// error is logged
	t.Run("fails-to-expand-bad-config-path", func(t *testing.T) {
		h.client.ClearToken()

		buf := new(bytes.Buffer)
		log.SetOutput(buf)
		defer log.SetOutput(os.Stdout)

		oldConfig := os.Getenv(EnvConfigFile)
		defer os.Setenv(EnvConfigFile, oldConfig)
		os.Setenv(EnvConfigFile, "~testdata/test.hcl")

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `error expanding directory "~testdata/test.hcl": cannot expand user-specific home dir`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})
}

func TestHelper_Get_FastTimeout(t *testing.T) {
	addr := os.Getenv(api.EnvVaultAddress)
	defer os.Setenv(api.EnvVaultAddress, addr)
	os.Setenv(api.EnvVaultAddress, "http://"+randomUUID(t)+".example.com")

	config := os.Getenv(EnvConfigFile)
	defer os.Setenv(EnvConfigFile, config)
	os.Setenv(EnvConfigFile, "testdata/valid.hcl")

	buf := new(bytes.Buffer)
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Error,
		Output: buf,
	})
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.SetMaxRetries(1)
	client.SetClientTimeout(1 * time.Second)
	client.ClearToken()

	h := NewHelper(&HelperOptions{
		Logger:      logger,
		AuthTimeout: 1,
		Client:      client,
	})
	_, _, err = h.Get("")
	if err == nil {
		t.Fatal("expected an error")
	}

	expected := `[ERROR] failed to get credentials within timeout (1s)`
	if !strings.Contains(buf.String(), expected) {
		t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
	}

}

func TestHelper_parseConfig(t *testing.T) {
	configFile := os.Getenv(EnvConfigFile)
	defer os.Setenv(EnvConfigFile, configFile)

	h := NewHelper(&HelperOptions{
		Logger: hclog.NewNullLogger(),
	})

	cases := []struct {
		name string
		file string
		err  string
	}{
		{
			"file-doesnt-exist",
			"testdata/nonexistent.hcl",
			"stat testdata/nonexistent.hcl: no such file or directory",
		},
		{
			"provided-directory",
			"testdata",
			"location is a directory, not a file",
		},
		{
			"empty-file",
			"testdata/empty-file.hcl",
			"no 'auto_auth' block found",
		},
		{
			"no-method",
			"testdata/no-method.hcl",
			"error parsing 'auto_auth': error parsing 'method': one and only one \"method\" block is required",
		},
		{
			"no-mount-path",
			"testdata/no-mount-path.hcl",
			"",
		},
		{
			"valid",
			"testdata/valid.hcl",
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv(EnvConfigFile, tc.file)

			_, err := h.parseConfig(tc.file)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Results differ:\n%v", cmp.Diff(err.Error(), tc.err))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// if tc.secret != secret {
			// 	t.Fatalf("Results differ:\n%v", cmp.Diff(tc.secret, secret))
			// }
			// return
		})
	}
}

func TestHelper_buildSinks(t *testing.T) {
	logger := hclog.NewNullLogger()
	client, err := api.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	validConfig := &sink.SinkConfig{
		Logger: logger.Named("sink.file"),
		Config: map[string]interface{}{
			"path": "testdata/test-sink",
		},
		Client: client,
	}
	fs, err := file.NewFileSink(validConfig)
	if err != nil {
		t.Fatal(err)
	}
	validConfig.Sink = fs

	h := NewHelper(&HelperOptions{
		Logger: logger,
		Client: client,
	})

	cases := []struct {
		name    string
		configs []*config.Sink
		err     string
		sinks   []*sink.SinkConfig
	}{
		{
			"bad-type",
			[]*config.Sink{
				&config.Sink{
					Type: "kitchen",
				},
			},
			`unknown sink type "kitchen"`,
			nil,
		},
		{
			"new-file-sink-error",
			[]*config.Sink{
				&config.Sink{
					Type: "file",
					Config: map[string]interface{}{
						"no": "path!",
					},
				},
			},
			"error creating file sink: 'path' not specified for file sink",
			nil,
		},
		{
			"success",
			[]*config.Sink{
				&config.Sink{
					Type: "file",
					Config: map[string]interface{}{
						"path": "testdata/test-sink",
					},
				},
			},
			"",
			[]*sink.SinkConfig{validConfig},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sinks, err := h.buildSinks(tc.configs)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Results differ:\n%v", cmp.Diff(err.Error(), tc.err))
				}
				return
			}

			if !reflect.DeepEqual(sinks, tc.sinks) {
				t.Fatalf("Results differ:\n%v", cmp.Diff(tc.sinks, sinks))
			}
			return
		})
	}
}

func TestHelper_buildMethod(t *testing.T) {
	h := NewHelper(&HelperOptions{
		Logger: hclog.NewNullLogger(),
	})

	cases := []struct {
		name   string
		config *config.Method
		err    string
	}{
		{
			"aws",
			&config.Method{
				Type: "aws",
				Config: map[string]interface{}{
					"type": "ec2",
					"role": "dev-role",
				},
			},
			"",
		},
		{
			"azure",
			&config.Method{
				Type: "azure",
				Config: map[string]interface{}{
					"role":     "dev-test",
					"resource": "important-stuff",
				},
			},
			"",
		},
		{
			"gcp",
			&config.Method{
				Type: "gcp",
				Config: map[string]interface{}{
					"type": "gce",
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"jwt",
			&config.Method{
				Type: "jwt",
				Config: map[string]interface{}{
					"path": "jwt/token",
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"kubernetes",
			&config.Method{
				Type: "kubernetes",
				Config: map[string]interface{}{
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"approle",
			&config.Method{
				Type: "approle",
				Config: map[string]interface{}{
					"role_id_file_path":   "path/to/role/id",
					"secret_id_file_path": "path/to/secret/id",
				},
			},
			"",
		},
		{
			"unknown",
			&config.Method{
				Type:   "fingerprint",
				Config: map[string]interface{}{},
			},
			`unknown auth method "fingerprint"`,
		},
		{
			"error",
			&config.Method{
				Type:   "alicloud",
				Config: map[string]interface{}{},
			},
			"error creating alicloud auth method: 'role' is required but is not provided",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.buildMethod(tc.config)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Results differ:\n%v", cmp.Diff(err.Error(), tc.err))
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNewVaultClient(t *testing.T) {
	oldEnv := awstesting.StashEnv()
	defer awstesting.PopEnv(oldEnv)

	cases := []struct {
		name   string
		env    map[string]string
		method *config.Method
		err    string
	}{
		{
			"env-precedence",
			map[string]string{
				api.EnvVaultAddress: "http://127.0.0.1:8200",
			},
			&config.Method{
				Config: map[string]interface{}{
					strings.ToLower(api.EnvVaultAddress): "http://127.0.0.1:8201",
				},
			},
			"",
		},
		{
			"config-lowercase",
			map[string]string{},
			&config.Method{
				Config: map[string]interface{}{
					strings.ToLower(api.EnvVaultAddress): "http://127.0.0.1:8201",
				},
			},
			"",
		},
		{
			"config-uppercase",
			map[string]string{},
			&config.Method{
				Config: map[string]interface{}{
					api.EnvVaultAddress: "http://127.0.0.1:8201",
				},
			},
			"",
		},
		{
			"config-error",
			map[string]string{},
			&config.Method{
				Config: map[string]interface{}{
					strings.ToLower(api.EnvVaultAddress): map[string]interface{}{
						"not": "stringable!",
					},
				},
			},
			"field 'auto_auth.method.config.VAULT_ADDR' could not be converted to a string",
		},
		{
			"new-client-error",
			map[string]string{
				api.EnvRateLimit: "asdf",
			},
			&config.Method{
				Config: map[string]interface{}{},
			},
			"error encountered setting up default configuration: VAULT_RATE_LIMIT was provided but incorrectly formatted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for env, new := range tc.env {
				old := os.Getenv(env)
				defer os.Setenv(env, old)
				os.Setenv(env, new)
			}

			client, err := newVaultClient(tc.method)
			if tc.err != "" {
				if err == nil {
					t.Fatal("expected an error but didn't receive one")
				}
				if err.Error() != tc.err {
					t.Fatalf("Errors differ:\n%v", cmp.Diff(tc.err, err.Error()))
				}
				return
			}

			if len(tc.env) > 0 {
				for env, val := range tc.env {
					switch env {
					case api.EnvVaultAddress:
						if client.Address() != val {
							t.Fatalf("Vault client addresses differ:\n%v", cmp.Diff(client.Address, val))
						}
						delete(tc.method.Config, api.EnvVaultAddress)
						delete(tc.method.Config, strings.ToLower(api.EnvVaultAddress))
					case api.EnvVaultToken:
						if client.Token() != val {
							t.Fatalf("Vault tokens differ:\n%v", cmp.Diff(client.Token(), val))
						}
						delete(tc.method.Config, api.EnvVaultToken)
						delete(tc.method.Config, strings.ToLower(api.EnvVaultToken))
					default:
						t.Fatalf("environment variable %q is not supported for this unit test", env)
					}
				}
			}

			if len(tc.method.Config) > 0 {
				for env, val := range tc.method.Config {
					switch env {
					case api.EnvVaultAddress, strings.ToLower(api.EnvVaultAddress):
						s, ok := val.(string)
						if !ok {
							t.Fatalf("config %s could not be cast to string", env)
						}
						if client.Address() != s {
							t.Fatalf("Vault client addresses differ:\n%v", cmp.Diff(client.Address(), s))
						}
					case api.EnvVaultToken, strings.ToLower(api.EnvVaultToken):
						s, ok := val.(string)
						if !ok {
							t.Fatalf("config %s could not be cast to string", env)
						}
						if client.Token() != s {
							t.Fatalf("Vault tokens differ:\n%v", cmp.Diff(client.Token(), s))
						}
					default:
						t.Fatalf("environment variable %q is not supported for this unit test", env)
					}
				}
			}

		})
	}
}

func TestNewVaultClient_Token(t *testing.T) {

	t.Run("config", func(t *testing.T) {
		oldToken := os.Getenv(api.EnvVaultToken)
		defer os.Setenv(api.EnvVaultToken, oldToken)
		os.Unsetenv(api.EnvVaultToken)

		token := randomUUID(t)

		method := &config.Method{
			Type: "token",
			Config: map[string]interface{}{
				"token": token,
			},
		}

		client, err := newVaultClient(method)
		if err != nil {
			t.Fatal(err)
		}

		if client.Token() != token {
			t.Fatalf("Client token differs from expected token:\n%v", cmp.Diff(client.Token(), token))
		}
	})

	t.Run("env", func(t *testing.T) {
		token := randomUUID(t)

		oldToken := os.Getenv(api.EnvVaultToken)
		defer os.Setenv(api.EnvVaultToken, oldToken)
		os.Setenv(api.EnvVaultToken, token)

		method := &config.Method{
			Type: "token",
		}

		client, err := newVaultClient(method)
		if err != nil {
			t.Fatal(err)
		}

		if client.Token() != token {
			t.Fatalf("Client token differs from expected token:\n%v", cmp.Diff(client.Token(), token))
		}
	})

	oldToken := os.Getenv(api.EnvVaultToken)
	defer os.Setenv(api.EnvVaultToken, oldToken)
	os.Unsetenv(api.EnvVaultToken)

	cases := []struct {
		name   string
		method *config.Method
		err    string
	}{
		{
			"no-token-in-config",
			&config.Method{
				Type: "token",
			},
			"missing 'auto_auth.method.config.token' value",
		},
		{
			"token-not-string",
			&config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": 26,
				},
			},
			"could not convert 'auto_auth.method.config.token' config value to string",
		},
		{
			"empty-token",
			&config.Method{
				Type: "token",
				Config: map[string]interface{}{
					"token": "",
				},
			},
			`No token provided. If the "token" auto_auth method is to be used, either the VAULT_TOKEN environment variable must be set or the 'auto_auth.method.config.token' field of the configuration file must be set.`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newVaultClient(tc.method)
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Error() != tc.err {
				t.Fatalf("Errors differ:\n%v", cmp.Diff(err.Error(), tc.err))
			}
		})
	}
}

func randomUUID(t *testing.T) string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
