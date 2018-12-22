package helper

import (
	// "bytes"
	"os"
	// "strings"
	"reflect"
	"testing"

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

func TestHelperGet_Logger(t *testing.T) {
	t.SkipNow()
}

func TestHelperGet_Cache(t *testing.T) {
	t.SkipNow()
}

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
