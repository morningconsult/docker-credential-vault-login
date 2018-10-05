package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/mitchellh/go-homedir"
)

type VaultAuthMethod string

const (
	VaultAuthMethodAWSIAM = VaultAuthMethod("iam")

	VaultAuthMethodAWSEC2 = VaultAuthMethod("ec2")

	VaultAuthMethodToken = VaultAuthMethod("token")

	DefaultConfigFilePath string = "/etc/docker-credential-vault-login/config.json"

	EnvConfigFilePath string = "DOCKER_CREDS_CONFIG_FILE"
)

type CredHelperConfig struct {
	// Method is the method Vault will use to
	// authenticate a user. Accepted values include
	// "token", "iam", and "ec2". This field is
	// always required
	Method VaultAuthMethod `json:"auth_method"`

	// Role is the Vault role which has been configured
	// to be able to authenticate via the EC2 or IAM
	// method (this field is only required when either
	// "iam" or "ec2" is chosen as the authentication
	// method).
	Role string `json:"role"`

	// Secret is the path in Vault at which the Docker
	// credentials are stored (e.g. "secret/foo/bar").
	// This field is always required.
	Secret string `json:"secret_path"`

	// ServerID is used as the value of the
	// X-Vault-AWS-IAM-Server-ID when Vault makes an
	// sts:GetCallerIdentity request to AWS. This field
	// is optional and is only used when "iam" is chosen
	// as the authentication method.
	ServerID string `json:"iam_server_id_header_value"`

	// MountPath is used to specify the path at which the
	// aws secrets engine is enable (if at all). If this
	// is empty, the default mount path "aws" will be
	// used instead.
	MountPath string `json:"aws_mount_path"`

	// Path is the full path to the config.json file.
	// This field is primarily used for error logging.
	Path string `json:"-"`
}

// GetCredHelperConfig first searches for the config.json
// file at the DOCKER_CREDS_CONFIG_FILE environment variable
// if it is set, otherwise it searches for it at the
// DefaultConfigFilePath location. If it is found in neither
// location, GetCredHelperConfig will return an error.
// If it finds the config.json file, GetCredHelperConfig
// will parse and validate it.
func GetCredHelperConfig() (*CredHelperConfig, error) {
	cfg, err := parseConfigFile()
	if err != nil {
		return nil, err
	}

	if err = cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseConfigFile() (*CredHelperConfig, error) {
	var rawPath = DefaultConfigFilePath

	if v := os.Getenv(EnvConfigFilePath); v != "" {
		rawPath = v
	}

	path, err := homedir.Expand(rawPath)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	var cfg = new(CredHelperConfig)
	if err = jsonutil.DecodeJSONFromReader(file, cfg); err != nil {
		return cfg, err
	}

	cfg.Path = path
	return cfg, nil
}

func (c *CredHelperConfig) validate() error {
	var errors []string

	method := c.Method

	switch method {
	case "":
		errors = append(errors, `No Vault authentication method ("auth_method") is provided`)
	case VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2:
		if c.Role == "" {
			errors = append(errors, fmt.Sprintf("%s %s", `No Vault role ("role") is`,
				"provided (required when the AWS authentication method is chosen)"))
		}
	case VaultAuthMethodToken:
		if v := os.Getenv("VAULT_TOKEN"); v == "" {
			errors = append(errors, fmt.Sprintf("VAULT_TOKEN environment variable is not set"))
		}
	default:
		errors = append(errors, fmt.Sprintf("%s %s %q (must be one of %q, %q, or %q)",
			"Unrecognized Vault authentication method", `("auth_method") value`,
			method, VaultAuthMethodAWSIAM, VaultAuthMethodAWSEC2, VaultAuthMethodToken))
	}

	if c.Secret == "" {
		errors = append(errors, fmt.Sprintf("%s %s", "No path to the location of",
			`your secret in Vault ("secret_path") is provided`))
	}

	if len(errors) > 0 {
		return fmt.Errorf("Configuration file %s has the following errors:\n* %s",
			c.Path, strings.Join(errors, "\n* "))
	}

	if c.MountPath == "" {
		c.MountPath = "aws"
	}

	return nil
}
