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
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/helper/dhutil"
	"golang.org/x/xerrors"
)

const EnvDiffieHellmanPrivateKey = "DCVL_DH_PRIV_KEY"

type PrivateKeyInfo struct {
	Curve25519PrivateKey []byte `json:"curve25519_private_key"`
}

// GetCachedTokens attempts to read tokens from the sink(s) and
// return them. Currently, this function only supports "file" sinks.
func GetCachedTokens(logger hclog.Logger, sinks []*config.Sink, client *api.Client) []string {
	tokens := make([]string, 0, len(sinks))
	for i, sink := range sinks {
		switch sink.Type {
		case "file":
		default:
			continue
		}

		pathRaw, ok := sink.Config["path"]
		if !ok {
			logger.Error(fmt.Sprintf("'path' not specified for sink %d", i))
			continue
		}

		path, ok := pathRaw.(string)
		if !ok {
			logger.Error(fmt.Sprintf("value of 'path' of sink %d could not be converted to string", i))
			continue
		}

		fileData, err := ioutil.ReadFile(path)
		if err != nil {
			logger.Error(fmt.Sprintf("error opening file sink %s", path), "error", err)
			continue
		}

		token := string(fileData)

		// Token is encrypted
		if sink.DHType != "" {
			var err error
			token, err = decryptToken(path, token, sink.AAD, sink.Config)
			if err != nil {
				logger.Error(fmt.Sprintf("error decrypting file sink %s", path), "error", err)
				continue
			}
		}

		// Secret is TTL-wrapped
		if sink.WrapTTL != 0 {
			var err error
			token, err = unwrapToken(token, client)
			if err != nil {
				logger.Error(fmt.Sprintf("error TTL-unwrapping token in file sink %s", path), "error", err)
				continue
			}
		}
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func decryptToken(path, token string, aad string, config map[string]interface{}) (string, error) {
	var resp dhutil.Envelope
	if err := json.Unmarshal([]byte(token), &resp); err != nil {
		return "", xerrors.Errorf("error JSON-decoding file sink %s: %w", path, err)
	}

	var privateKey []byte
	if v := os.Getenv(EnvDiffieHellmanPrivateKey); v != "" {
		var err error
		privateKey, err = base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "", xerrors.Errorf("error base64-decoding $%s: %w", EnvDiffieHellmanPrivateKey, err)
		}
	}

	if len(privateKey) == 0 {
		dhPrivKeyFileRaw, ok := config["dh_priv"]
		if !ok {
			return "", xerrors.Errorf(
				"If the cached token is encrypted, the Diffie-Hellman private "+
					"key should be specified with the environment variable %s as a base64-encoded "+
					"string or in the 'file.config.dh_priv' field of the config file %s as a path "+
					"to a JSON-encoded PrivateKeyInfo structure",
				path,
				EnvDiffieHellmanPrivateKey,
			)
		}

		dhPrivKeyFile, ok := dhPrivKeyFileRaw.(string)
		if !ok {
			return "", xerrors.Errorf(
				"'dh_priv' field of file sink at %s cannot be converted to string",
				path,
			)
		}

		file, err := os.Open(dhPrivKeyFile)
		if err != nil {
			return "", xerrors.Errorf("error opening 'dh_priv' file %s: %w", dhPrivKeyFile, err)
		}
		defer file.Close()

		var pkInfo PrivateKeyInfo
		if err = json.NewDecoder(file).Decode(&pkInfo); err != nil {
			return "", xerrors.Errorf("error JSON-decoding file %s: %w", dhPrivKeyFile, err)
		}

		if len(pkInfo.Curve25519PrivateKey) == 0 {
			return "", xerrors.Errorf("field 'curve25519_private_key' of file %s is empty", dhPrivKeyFile)
		}

		privateKey = pkInfo.Curve25519PrivateKey
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

func unwrapToken(token string, client *api.Client) (string, error) {
	var wrapInfo api.SecretWrapInfo
	if err := json.Unmarshal([]byte(token), &wrapInfo); err != nil {
		return "", xerrors.Errorf("error JSON-decoding TTL-wrapped secret: %w", err)
	}

	client.SetToken(wrapInfo.Token)
	secret, err := client.Logical().Unwrap("")
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
