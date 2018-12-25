package helper

import (
	"bytes"
	"path/filepath"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"github.com/hashicorp/vault/builtin/credential/approle"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"github.com/aws/aws-sdk-go/awstesting"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/go-uuid"
)

func TestNewHelper(t *testing.T) {
	h := NewHelper(&HelperOptions{
		AuthTimeout: 1,
	})

	if h.authTimeout != time.Duration(1) * time.Second {
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

func TestHelper_Get_logger(t *testing.T) {
	config := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, config)
	os.Setenv(envConfigFile, "testdata/empty-file.hcl") // Ensures that parseConfig with throw an error

	logdir := os.Getenv("DOCKER_CREDS_LOG_DIR")
	defer os.Setenv("DOCKER_CREDS_LOG_DIR", logdir)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("DOCKER_CREDS_LOG_DIR", testdata)

	h := NewHelper(nil)

	_, _, err = h.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
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

	expected := `[ERROR] helper.get: error parsing configuration file testdata/empty-file.hcl: error="error parsing 'auto_auth': one and only one "auto_auth" block is required"`
	if !strings.Contains(string(data), expected) {
		t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, string(data))
	}
}

func TestHelper_Get_config(t *testing.T) {
	config := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, config)
	os.Setenv(envConfigFile, "testdata/empty-file.hcl")

	h := NewHelper(nil)

	_, _, err := h.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestHelper_Get_newVaultClient(t *testing.T) {
	oldConfig := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, oldConfig)
	os.Setenv(envConfigFile, "testdata/valid.hcl")

	oldLog := os.Getenv("DOCKER_CREDS_LOG_DIR")
	defer os.Setenv("DOCKER_CREDS_LOG_DIR", oldLog)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("DOCKER_CREDS_LOG_DIR", testdata)

	oldRL := os.Getenv(api.EnvRateLimit)
	defer os.Setenv(api.EnvRateLimit, oldRL)
	os.Setenv(api.EnvRateLimit, "not an int!") // Causes newVaultClient() to throw an error

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

	logdir := os.Getenv("DOCKER_CREDS_LOG_DIR")
	defer os.Setenv("DOCKER_CREDS_LOG_DIR", logdir)
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("DOCKER_CREDS_LOG_DIR", testdata)
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

	oldConfig := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, oldConfig)
	os.Setenv(envConfigFile, configFile)

	client.ClearToken()

	h := NewHelper(&HelperOptions{
		Client:      client,
		AuthTimeout: 3,
	})

	// Test #1: Test that it can read authenticate, get a new token, and read the secret
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

	// Test #2: Test that it can read the secret using the cached token
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

	t.Run("can-disable-caching", func(t *testing.T) {
		h.client.ClearToken()
		h.logger = nil

		makeApproleFiles()

		os.Setenv(envDisableCaching, "true")
		defer os.Unsetenv(envDisableCaching)

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

		if _, err = os.Stat("testdata/token-sink"); os.IsExist(err) {
			t.Fatal("helper.Get() should not have cached a token")
		}
	})

	// Test #3: Ensure that if the client attempts to read the secret with
	// a bad token it fails
	t.Run("fails-when-bad-token-used", func(t *testing.T) {
		h.client.SetToken("bad token!")
		h.logger = nil

		makeApproleFiles()

		if _, _, err = h.Get(""); err == nil {
			t.Fatal("expected an error when client attempts to read secret with a bad token")
		}
	})

	// Test #4: Ensure that if the role does not have permission to read
	// the secret, it fails
	t.Run("fails-when-no-policy", func(t *testing.T) {
		client.SetToken(rootToken)

		if err = client.Sys().DeletePolicy("dev-policy"); err != nil {
			t.Fatal(err)
		}

		h.client.ClearToken()
		h.logger = nil

		makeApproleFiles()

		if _, _, err = h.Get(""); err == nil {
			t.Fatal("expected an error when role attempts to read secret with without permission")
		}
	})

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

		_, _, err = h.Get("")
		if err == nil {
			t.Fatal("expected an error")
		}

		expected := `[ERROR] error building sinks: error="unknown sink type "kitchen""`
		if !strings.Contains(buf.String(), expected) {
			t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
		}
	})

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
}

func TestHelper_Get_FastTimeout(t *testing.T) {
	addr := os.Getenv(api.EnvVaultAddress)
	defer os.Setenv(api.EnvVaultAddress, addr)
	os.Setenv(api.EnvVaultAddress, "http://" + randomUUID(t) + ".example.com")

	config := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, config)
	os.Setenv(envConfigFile, "testdata/valid.hcl")

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

	expected := `[ERROR] auth.handler: error authenticating: error="context deadline exceeded"`
	if !strings.Contains(buf.String(), expected) {
		t.Fatalf("Expected log file to contain:\n\t%q\nGot this instead:\n\t%s", expected, buf.String())
	}
	
}

func TestHelper_parseConfig(t *testing.T) {
	configFile := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, configFile)

	h := NewHelper(&HelperOptions{
		Logger: hclog.NewNullLogger(),
	})

	cases := []struct {
		name   string
		file   string
		err    string
		secret string
	}{
		{
			"file-doesnt-exist",
			"testdata/nonexistent.hcl",
			"stat testdata/nonexistent.hcl: no such file or directory",
			"",
		},
		{
			"provided-directory",
			"testdata",
			"location is a directory, not a file",
			"",
		},
		{
			"empty-file",
			"testdata/empty-file.hcl",
			"error parsing 'auto_auth': one and only one \"auto_auth\" block is required",
			"",
		},
		{
			"no-method",
			"testdata/no-method.hcl",
			"error parsing 'auto_auth': error parsing 'method': one and only one \"method\" block is required",
			"",
		},
		{
			"no-secret",
			"testdata/no-secret.hcl",
			"field 'auto_auth.method.config.secret' not found",
			"",
		},
		{
			"secret-not-string",
			"testdata/secret-not-string.hcl",
			"field 'auto_auth.method.config.secret' could not be converted to string",
			"",
		},
		{
			"no-mount-path",
			"testdata/no-mount-path.hcl",
			"",
			"secret/docker/creds",
		},
		{
			"valid",
			"testdata/valid.hcl",
			"",
			"secret/docker/creds",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Setenv(envConfigFile, tc.file)

			_, secret, err := h.parseConfig(tc.file)
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
			if tc.secret != secret {
				t.Fatalf("Results differ:\n%v", cmp.Diff(tc.secret, secret))
			}
			return
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
					Type:   "file",
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
					Type:   "file",
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
				Type:   "aws",
				Config: map[string]interface{}{
					"type": "iam",
					"role": "dev-role",
				},
			},
			"",
		},
		{
			"azure",
			&config.Method{
				Type:   "azure",
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
				Type:   "gcp",
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
				Type:   "jwt",
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
				Type:   "kubernetes",
				Config: map[string]interface{}{
					"role": "dev-test",
				},
			},
			"",
		},
		{
			"approle",
			&config.Method{
				Type:   "approle",
				Config: map[string]interface{}{
					"role_id_file_path": "path/to/role/id",
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
		config map[string]interface{}
		err    string
	}{
		{
			"env-precedence",
			map[string]string{
				api.EnvVaultAddress: "http://127.0.0.1:8200",
			},
			map[string]interface{}{
				strings.ToLower(api.EnvVaultAddress): "http://127.0.0.1:8201",
			},
			"",
		},
		{
			"config-lowercase",
			map[string]string{},
			map[string]interface{}{
				strings.ToLower(api.EnvVaultAddress): "http://127.0.0.1:8201",
			},
			"",
		},
		{
			"config-uppercase",
			map[string]string{},
			map[string]interface{}{
				api.EnvVaultAddress: "http://127.0.0.1:8201",
			},
			"",
		},
		{
			"config-error",
			map[string]string{},
			map[string]interface{}{
				strings.ToLower(api.EnvVaultAddress): map[string]interface{}{
					"not": "stringable!",
				},
			},
			"field 'auto_auth.method.config.VAULT_ADDR' could not be converted to a string",
		},
		{
			"new-client-error",
			map[string]string{
				api.EnvRateLimit: "asdf",
			},
			map[string]interface{}{},
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

			client, err := newVaultClient(tc.config)
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
						delete(tc.config, api.EnvVaultAddress)
						delete(tc.config, strings.ToLower(api.EnvVaultAddress))
					case api.EnvVaultToken:
						if client.Token() != val {
							t.Fatalf("Vault tokens differ:\n%v", cmp.Diff(client.Token(), val))
						}
						delete(tc.config, api.EnvVaultToken)
						delete(tc.config, strings.ToLower(api.EnvVaultToken))
					default:
						t.Fatalf("environment variable %q is not supported for this unit test", env)
					}
				}
			}

			if len(tc.config) > 0 {
				for env, val := range tc.config {
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

func randomUUID(t *testing.T) string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
