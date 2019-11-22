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

package cache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/helper/dhutil"
	"golang.org/x/xerrors"
)

// EnvDiffieHellmanPrivateKey is the path to Diffie Hellman private key
// used to decrypt an encrypted Vault token
const EnvDiffieHellmanPrivateKey = "DCVL_DH_PRIV_KEY"

type privateKeyInfo struct {
	Curve25519PrivateKey []byte `json:"curve25519_private_key"`
}

// GetCachedTokens attempts to read tokens from the sink(s) and
// return them. Currently, this function only supports "file" sinks.
func GetCachedTokens(logger hclog.Logger, sinks []*config.Sink, client *api.Client) []string {
	tokens := make([]string, 0, len(sinks))

	for i, sink := range sinks {
		switch sink.Type {
		case "file":
			token, err := readFileSink(sink.Config)
			if err != nil {
				logger.Error(fmt.Sprintf("error reading file sink %d", i+1), "error", err)
				continue
			}

			// Token is encrypted
			if sink.DHType != "" {
				var err error
				token, err = decryptToken(token, sink.AAD, sink.Config)
				if err != nil { // nolint: wsl
					logger.Error(fmt.Sprintf("error decrypting file sink %d", i+1), "error", err)
					continue
				}
			}

			// Secret is TTL-wrapped
			if sink.WrapTTL != 0 {
				var err error
				token, err = unwrapToken(token, client.Logical().Unwrap)
				if err != nil { // nolint: wsl
					logger.Error(fmt.Sprintf("error TTL-unwrapping token in file sink %d", i+1), "error", err)
					continue
				}
			}

			if token != "" {
				tokens = append(tokens, token)
			}
		default:
			logger.Info(fmt.Sprintf("unsupported sink type: %s", sink.Type))
		}
	}

	return tokens
}

func readFileSink(config map[string]interface{}) (string, error) {
	pathRaw, ok := config["path"]
	if !ok {
		return "", xerrors.New("'path' not specified for sink")
	}

	path, ok := pathRaw.(string)
	if !ok {
		return "", xerrors.New("value of 'path' of sink could not be converted to string")
	}

	fileData, err := ioutil.ReadFile(path) // nolint: gosec
	if err != nil {
		return "", xerrors.Errorf("error opening file sink %s: %w", path, err)
	}

	return string(fileData), nil
}

func decryptToken(token string, aad string, config map[string]interface{}) (string, error) {
	var resp dhutil.Envelope
	if err := json.Unmarshal([]byte(token), &resp); err != nil {
		return "", xerrors.Errorf("error JSON-decoding file sink: %w", err)
	}

	privateKey, err := readDHPrivateKey(config)
	if err != nil {
		return "", xerrors.Errorf("error reading Diffie-Hellman private key file: %w", err)
	}

	if len(privateKey) == 0 {
		return "", xerrors.New("no valid Diffie-Hellman private key found")
	}

	aesKey, err := dhutil.GenerateSharedKey(privateKey, resp.Curve25519PublicKey)
	if err != nil {
		return "", xerrors.Errorf("error creating AES-GCM key: %w", err)
	}

	if len(aesKey) == 0 {
		return "", xerrors.New("got empty AES key")
	}

	data, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte(aad))
	if err != nil {
		return "", xerrors.Errorf("error decrypting token: %w", err)
	}

	return string(data), nil
}

func parseDHPrivateKeyEnv(key string) ([]byte, error) {
	encoded := os.Getenv(key)
	if encoded == "" {
		return nil, xerrors.Errorf("environment variable %s is not set", key)
	}

	privateKey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, xerrors.Errorf("error base64-decoding %s: %w", key, err)
	}

	return privateKey, nil
}

func parseDHPrivateKeyFile(path string) ([]byte, error) {
	file, err := os.Open(path) // nolint: gosec
	if err != nil {
		return nil, xerrors.Errorf("error opening 'dh_priv' file %s: %w", path, err)
	}

	defer file.Close()

	var pkInfo privateKeyInfo
	if err = json.NewDecoder(file).Decode(&pkInfo); err != nil {
		return nil, xerrors.Errorf("error JSON-decoding file %s: %w", path, err)
	}

	if len(pkInfo.Curve25519PrivateKey) == 0 {
		return nil, xerrors.Errorf("field 'curve25519_private_key' of file %s is empty", path)
	}

	return pkInfo.Curve25519PrivateKey, nil
}

func readDHPrivateKey(config map[string]interface{}) ([]byte, error) {
	var dhPrivKeyEnv string

	// This is here only for backwards compatibility
	if os.Getenv(EnvDiffieHellmanPrivateKey) != "" {
		dhPrivKeyEnv = EnvDiffieHellmanPrivateKey
	}

	if dhPrivKeyEnv == "" {
		dhPrivKeyEnv, _ = config["dh_priv_env"].(string)
	}

	// Try getting Diffie-Hellman private key from environment first
	if dhPrivKeyEnv != "" {
		return parseDHPrivateKeyEnv(dhPrivKeyEnv)
	}

	// If the environment variable is not set, try getting the
	// Diffie-Hellman private key from a file
	dhPrivKeyFile, ok := config["dh_priv"].(string)

	// Return an error if no Diffie-Hellman key is provided in neither
	// the environment nor by a file
	if !ok {
		return nil, errors.New("no Diffie-Hellman private key provided")
	}

	// Try reading the Diffie-Hellman private key from file
	return parseDHPrivateKeyFile(dhPrivKeyFile)
}

type unwrapFunc func(token string) (*api.Secret, error)

func unwrapToken(token string, unwrap unwrapFunc) (string, error) {
	var wrapInfo api.SecretWrapInfo
	if err := json.Unmarshal([]byte(token), &wrapInfo); err != nil {
		return "", xerrors.Errorf("error JSON-decoding TTL-wrapped secret: %w", err)
	}

	secret, err := unwrap(wrapInfo.Token)
	if err != nil {
		return "", xerrors.Errorf("error unwrapping token: %w", err)
	}

	token, err = secret.TokenID()
	if err != nil {
		return "", xerrors.Errorf("error reading token from Vault response: %w", err)
	}

	if token == "" {
		if secret.Data != nil && secret.Data["token"] != nil {
			if t, ok := secret.Data["token"].(string); ok {
				token = t
			}
		}
	}

	return token, nil
}
