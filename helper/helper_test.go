package helper

import (
	// "bytes"
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
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
)

func TestNewHelper(t *testing.T) {
	t.SkipNow()
}

func TestHelperGet_logger(t *testing.T) {
	config := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, config)
	os.Setenv(envConfigFile, "testdata/empty-file.hcl") // Ensures that parseConfig with throw an error

	logdir := os.Getenv("DOCKER_CREDS_LOG_DIR")
	defer os.Setenv("DOCKER_CREDS_LOG_DIR", logdir)
	os.Setenv("DOCKER_CREDS_LOG_DIR", "testdata")

	h := NewHelper(nil)

	_, _, err := h.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
	
	logfile := filepath.Join("testdata", fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))

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

func TestHelperGet_config(t *testing.T) {
	config := os.Getenv(envConfigFile)
	defer os.Setenv(envConfigFile, config)
	os.Setenv(envConfigFile, "testdata/empty-file.hcl")

	h := NewHelper(nil)

	_, _, err := h.Get("")
	if err == nil {
		t.Fatal("expected an error but didn't receive one")
	}
}

func TestHelperGet_newVaultClient(t *testing.T) {
	oldLog := os.Getenv("DOCKER_CREDS_LOG_DIR")
	defer os.Setenv("DOCKER_CREDS_LOG_DIR", oldLog)
	os.Setenv("DOCKER_CREDS_LOG_DIR", "testdata")

	oldRL := os.Getenv(api.EnvRateLimit)
	defer os.Setenv(api.EnvRateLimit, oldRL)
	os.Setenv(api.EnvRateLimit, "not an int!") // Causes newVaultClient() to throw an error

	h := NewHelper(nil)

	_, _, err := h.Get("")
	if err == nil {
		t.Fatal(err)
	}

	logfile := filepath.Join("testdata", fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))

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

// func TestHelperGet_cache(t *testing.T) {
// 	config := os.Getenv(envConfigFile)
// 	defer os.Setenv(envConfigFile, config)
// 	os.Setenv(envConfigFile, "testdata/testing.hcl")

// 	logdir := os.Getenv("DOCKER_CREDS_LOG_DIR")
// 	defer os.Setenv("DOCKER_CREDS_LOG_DIR", logdir)
// 	os.Setenv("DOCKER_CREDS_LOG_DIR", "testdata")

// 	h := NewHelper(nil)

// 	_, _, err := h.Get("")
// 	if err == nil {
// 		t.Fatal("expected an error but didn't receive one")
// 	}

// 	defer os.Remove("testdata/cache")

// 	data, err := ioutil.ReadFile(filepath.Join("testdata",fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02"))))
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	t.Log(string(data))
// }

func TestHelperGet_GetCreds(t *testing.T) {
	t.SkipNow()
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

			if tc.secret != secret {
				t.Fatalf("Results differ:\n%v", cmp.Diff(tc.secret, secret))
			}
			return
		})
	}
}

func TestHelperGet_buildSinks(t *testing.T) {
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
