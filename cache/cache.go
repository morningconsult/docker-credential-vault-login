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
)

const EnvDiffieHellmanPrivateKey = "DCVL_DH_PRIV_KEY"

type PrivateKeyInfo struct {
	Curve25519PrivateKey []byte `json:"curve25519_private_key"`
}

func GetCachedTokens(logger hclog.Logger, sinks []*config.Sink, client *api.Client) []string {
	var tokens []string

	for i, sink := range sinks {
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
			resp := new(dhutil.Envelope)
			if err := json.Unmarshal([]byte(token), resp); err != nil {
				logger.Error(fmt.Sprintf("error JSON-decoding file sink %s", path), "error", err)
				continue
			}

			var privateKey []byte
			if v := os.Getenv(EnvDiffieHellmanPrivateKey); v != "" {
				privateKey, err = base64.StdEncoding.DecodeString(v)
				if err != nil {
					logger.Error("error base64-decoding value of %s", "error", err)
				}
			}

			if len(privateKey) < 1 {
				dhPrivKeyFileRaw, ok := sink.Config["dh_priv"]
				if !ok {
					logger.Error(fmt.Sprintf("If the cached token is encrypted, the Diffie-Hellman private "+
						"key should be specified with the environment variable %s as a base64-encoded "+
						"string or in the 'file.config.dh_priv' field of the config file %s as a path "+
						"to a JSON-encoded PrivateKeyInfo structure", path, EnvDiffieHellmanPrivateKey))
					continue
				}

				dhPrivKeyFile, ok := dhPrivKeyFileRaw.(string)
				if !ok {
					logger.Error(fmt.Sprintf("'dh_priv' field of file sink %d of config file %s cannot be  "+
						"converted to string", i, path))
					continue
				}

				file, err := os.Open(dhPrivKeyFile)
				if err != nil {
					logger.Error(fmt.Sprintf("error opening 'dh_priv' file %s", dhPrivKeyFile), "error", err)
					continue
				}

				pkInfo := new(PrivateKeyInfo)
				if err = json.NewDecoder(file).Decode(pkInfo); err != nil {
					logger.Error(fmt.Sprintf("error JSON-decoding file %s", dhPrivKeyFile), "error", err)
					continue
				}

				if len(pkInfo.Curve25519PrivateKey) < 1 {
					logger.Error(fmt.Sprintf("field 'curve25519_private_key' of file %s is empty", dhPrivKeyFile))
					continue
				}

				privateKey = pkInfo.Curve25519PrivateKey
			}

			if len(privateKey) < 1 {
				logger.Error("no valid Diffie-Hellman private key found")
				continue
			}

			aesKey, err := dhutil.GenerateSharedKey(privateKey, resp.Curve25519PublicKey)
			if err != nil {
				logger.Error("error creating AES-GCM key", "error", err)
				continue
			}

			if len(aesKey) == 0 {
				logger.Error("got empty AES key")
				continue
			}

			data, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte(sink.AAD))
			if err != nil {
				logger.Error("error decrypting token", "error", err)
				continue
			}

			token = string(data)
		}

		// Secret is TTL-wrapped
		if sink.WrapTTL != 0 {
			wrapInfo := new(api.SecretWrapInfo)
			if err := json.Unmarshal([]byte(token), wrapInfo); err != nil {
				logger.Error("error JSON-decoding TTL-wrapped secret", "error", err)
				continue
			}

			client.SetToken(wrapInfo.Token)
			secret, err := client.Logical().Unwrap("")
			if err != nil {
				logger.Error("error unwrapping token", "error", err)
				continue
			}

			token, err = secret.TokenID()
			if err != nil {
				logger.Error("error reading token from Vault response", "error", err)
				continue
			}

			if token == "" {
				if secret.Data != nil && secret.Data["token"] != nil {
					if t, ok := secret.Data["token"].(string); ok {
						token = t
					}
				}
			}
		}

		if token != "" {
			tokens = append(tokens, token)
		}
	}
	return tokens
}
