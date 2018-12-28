package cache

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/dhutil"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/command/agent/config"
)

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
			if err := jsonutil.DecodeJSON([]byte(token), resp); err != nil {
				logger.Error(fmt.Sprintf("error JSON-decoding file sink %s", path), "error", err)
				continue
			}

			dhPrivKeyFileRaw, ok := sink.Config["dh_priv"]
			if !ok {
				logger.Error(fmt.Sprintf("path to Diffie-Hellman private key (field 'dh_priv') not " +
					"specified in 'config' stanza of file sink %s", path))
				continue
			}

			dhPrivKeyFile, ok := dhPrivKeyFileRaw.(string)
			if !ok {
				logger.Error(fmt.Sprintf("'dh_priv' of file sink %s cannot be converted to string", path))
				continue
			}

			file, err := os.Open(dhPrivKeyFile)
			if err != nil {
				logger.Error(fmt.Sprintf("error opening 'dh_priv' file %s", dhPrivKeyFile), "error", err)
				continue
			}

			pkInfo := new(PrivateKeyInfo)
			if err = jsonutil.DecodeJSONFromReader(file, pkInfo); err != nil {
				logger.Error(fmt.Sprintf("error JSON-decoding file %s", dhPrivKeyFile), "error", err)
				continue
			}

			if len(pkInfo.Curve25519PrivateKey) < 1 {
				logger.Error(fmt.Sprintf("field 'curve25519_private_key' of file %s is empty", dhPrivKeyFile))
				continue
			}

			aesKey, err := dhutil.GenerateSharedKey(pkInfo.Curve25519PrivateKey, resp.Curve25519PublicKey)
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
			if err := jsonutil.DecodeJSON([]byte(token), wrapInfo); err != nil {
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

