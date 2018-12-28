package helper 

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/go-hclog"
	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/aws"
	"github.com/hashicorp/vault/command/agent/auth/azure"
	"github.com/hashicorp/vault/command/agent/auth/alicloud"
	"github.com/hashicorp/vault/command/agent/auth/gcp"
	"github.com/hashicorp/vault/command/agent/auth/jwt"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	"github.com/hashicorp/vault/command/agent/auth/approle"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"github.com/morningconsult/docker-credential-vault-login/cache"
	"github.com/morningconsult/docker-credential-vault-login/vault"
	"github.com/morningconsult/docker-credential-vault-login/logging"
)

const (
	EnvConfigFile = "DCVL_CONFIG_FILE"
	EnvDisableCaching = "DCVL_DISABLE_CACHE"
	EnvSecretPath = "DCVL_SECRET"
	defaultConfigFile = "/etc/docker-credential-vault-login/config.hcl"
)

var (
	notImplementedError = fmt.Errorf("not implemented")
	defaultAuthTimeout = 10 * time.Second
)

type HelperOptions struct {
	Logger      hclog.Logger
	Client      *api.Client
	AuthTimeout int64
}

type Helper struct {
	logger      hclog.Logger
	client      *api.Client
	authTimeout time.Duration
}

func NewHelper(opts *HelperOptions) *Helper {
	if opts == nil {
		opts = &HelperOptions{}
	}

	timeout := defaultAuthTimeout
	if opts.AuthTimeout != 0 {
		timeout = time.Duration(opts.AuthTimeout) * time.Second
	}

	return &Helper{
		logger:      opts.Logger,
		client:      opts.Client,
		authTimeout: timeout,
	}
}

func (h *Helper) Add(creds *credentials.Credentials) error {
	return notImplementedError
}

func (h *Helper) Delete(serverURL string) error {
	return notImplementedError
}

func (h *Helper) List() (map[string]string, error) {
	return nil, notImplementedError
}

func (h *Helper) Get(serverURL string) (string, string, error) {
	// Create new logger
	if h.logger == nil {
		opts := &hclog.LoggerOptions{
			Name:   "helper.get",
			Level:  hclog.Error,
			Output: os.Stderr,
		}

		w, err := logging.LogWriter(nil)
		if err != nil {
			h.logger.Error("error opening log file. Logging errors to stderr instead.", "error", err)
		} else {
			opts.Output = w
			defer w.Close()
		}

		h.logger = hclog.New(opts)
	}

	cachingEnabled := true
	if v := os.Getenv(EnvDisableCaching); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cachingEnabled = !b
		} else {
			h.logger.Error("Value of " + EnvDisableCaching + " could not be converted to boolean. Defaulting to false.", "error", err)
		}
	}

	configFile := defaultConfigFile
	if f := os.Getenv(EnvConfigFile); f != "" {
		configFile = f
	}

	config, err := h.parseConfig(configFile)
	if err != nil {
		h.logger.Error(fmt.Sprintf("error parsing configuration file %s", configFile), "error", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}

	secret := os.Getenv(EnvSecretPath)

	if secret == "" {
		secretRaw, ok := config.AutoAuth.Method.Config["secret"]
		if !ok {
			h.logger.Error(fmt.Sprintf("The path to the secret in which your Docker credentials are " +
				"stored must be specified via either (1) the %s environment variable or (2) the " +
				"field 'auto_auth.config.secret' of the config file.", EnvSecretPath))
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		secret, ok = secretRaw.(string)
		if !ok {
			h.logger.Error("field 'auto_auth.method.config.secret' could not be converted to string")
			return "", "", credentials.NewErrCredentialsNotFound()
		}
	}

	if h.client == nil {
		h.client, err = newVaultClient(config.AutoAuth.Method.Config)
		if err != nil {
			h.logger.Error("error creating new Vault API client", "error", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}
	}

	if h.client.Token() == "" {
		if cachingEnabled {
			cloned, err := h.client.Clone()
			if err != nil {
				h.logger.Error("error cloning Vault API client", "error", err)
				return "", "", credentials.NewErrCredentialsNotFound()
			}

			// Get any cached tokens
			cachedTokens := cache.GetCachedTokens(h.logger.Named("cache"), config.AutoAuth.Sinks, cloned)
			if len(cachedTokens) < 1 {
				h.logger.Info("No cached token(s) were read. Re-authenticating.")
			}

			// Renew the cached tokens
			for _, token := range cachedTokens {
				if _, err := h.client.Auth().Token().RenewTokenAsSelf(token, 0); err != nil {
					h.logger.Error("error renewing token", "error", err)
				}
			}

			// Use any token to get credentials
			for _, token := range cachedTokens {
				h.client.SetToken(token)

				// Get credentials
				creds, err := vault.GetCredentials(secret, h.client)
				if err != nil {
					h.logger.Error("error reading secret from Vault", "error", err)
					continue
				}
				return creds.Username, creds.Password, nil
			}
		}

		// Failed to read secret with cached token. Reauthenticate.
		h.client.ClearToken()

		sinks, err := h.buildSinks(config.AutoAuth.Sinks)
		if err != nil {
			h.logger.Error("error building sinks", "error", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		method, err := h.buildMethod(config.AutoAuth.Method)
		if err != nil {
			h.logger.Error("error building method", "error", err)
			return "", "", credentials.NewErrCredentialsNotFound()
		}

		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        h.logger.Named("sink.server"),
			Client:        h.client,
			ExitAfterAuth: true,
		})

		ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
			Logger:  h.logger.Named("auth.handler"),
			Client:  h.client,
			WrapTTL: config.AutoAuth.Method.WrapTTL,
		})

		ctx, cancel := context.WithTimeout(context.Background(), h.authTimeout)

		newTokenCh := make(chan string)

		go ah.Run(ctx, method)
		go ss.Run(ctx, newTokenCh, sinks)

		var token string
		select {
		case <-ctx.Done():
			h.logger.Error(fmt.Sprintf("failed to get credentials within timeout (%s)", h.authTimeout.String()))
			<-ah.DoneCh
			<-ss.DoneCh
			return "", "", credentials.NewErrCredentialsNotFound()
		case token = <-ah.OutputCh:
			// will have to unwrap token if wrapped
			h.logger.Info("successfully authenticated")
		}

		if cachingEnabled {
			newTokenCh <- token
			select {
			case <-ctx.Done():
				h.logger.Error(fmt.Sprintf("failed to write token to sink(s) within the timeout (%s)", h.authTimeout.String()))
				<-ah.DoneCh
				<-ss.DoneCh
				return "", "", credentials.NewErrCredentialsNotFound()
			case <-ss.DoneCh:
			}
		}

		cancel()
		<-ah.DoneCh

		h.client.SetToken(token)
	}

	// Get credentials
	creds, err := vault.GetCredentials(secret, h.client)
	if err != nil {
		h.logger.Error("error reading secret from Vault", "error", err)
		return "", "", credentials.NewErrCredentialsNotFound()
	}
	return creds.Username, creds.Password, nil
}

func (h *Helper) parseConfig(configFile string) (*config.Config, error) {
	config, err := config.LoadConfig(configFile, h.logger)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errors.New("no configuration read. Please provide the configuration file with the " +
			EnvConfigFile + " environment variable.")
	}

	if config.AutoAuth == nil {
		return nil, errors.New("no 'auto_auth' block found")
	}

	return config, nil
}

func (h *Helper) buildSinks(ss []*config.Sink) ([]*sink.SinkConfig, error) {
	var sinks []*sink.SinkConfig
	for _, sc := range ss {
		switch sc.Type {
		case "file":
			config := &sink.SinkConfig{
				Logger:  h.logger.Named("sink.file"),
				Config:  sc.Config,
				Client:  h.client,
				WrapTTL: sc.WrapTTL,
				DHType:  sc.DHType,
				DHPath:  sc.DHPath,
				AAD:     sc.AAD,
			}
			s, err := file.NewFileSink(config)
			if err != nil {
				return nil, fmt.Errorf("error creating file sink: %v", err)
			}
			config.Sink = s
			sinks = append(sinks, config)
		default:
			return nil, fmt.Errorf("unknown sink type %q", sc.Type)
		}
	}
	return sinks, nil
}

func (h *Helper) buildMethod(config *config.Method) (auth.AuthMethod, error) {
	var (
		method auth.AuthMethod
		err error
	)

	authConfig := &auth.AuthConfig{
		Logger:    h.logger.Named(fmt.Sprintf("auth.%s", config.Type)),
		MountPath: config.MountPath,
		Config:    config.Config,
	}
	switch config.Type {
	case "alicloud":
		method, err = alicloud.NewAliCloudAuthMethod(authConfig)
	case "aws":
		method, err = aws.NewAWSAuthMethod(authConfig)
	case "azure":
		method, err = azure.NewAzureAuthMethod(authConfig)
	case "gcp":
		method, err = gcp.NewGCPAuthMethod(authConfig)
	case "jwt":
		method, err = jwt.NewJWTAuthMethod(authConfig)
	case "kubernetes":
		method, err = kubernetes.NewKubernetesAuthMethod(authConfig)
	case "approle":
		method, err = approle.NewApproleAuthMethod(authConfig)
	default:
		return nil, fmt.Errorf("unknown auth method %q", config.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating %s auth method: %v", config.Type, err)
	}
	return method, nil
}
