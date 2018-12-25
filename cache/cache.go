package cache

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/dhutil"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/command/agent/config"
)

type PrivateKeyInfo struct {
	Curve25519PrivateKey string `json:"curve25519_private_key"`
}

func GetCachedTokens(sinks []*config.Sink, client *api.Client) ([]string, error) {
	var tokens []string

	for _, sink := range sinks {
		pathRaw, ok := sink.Config["path"]
		if !ok {
			return nil, errors.New("'path' not specified for file sink")
		}

		path, ok := pathRaw.(string)
		if !ok {
			return nil, errors.New("file sink path could not be converted to string")
		}

		fileData, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("error opening file sink %s: %v", path, err)
		}

		token := string(fileData)

		// Token is encrypted
		if sink.DHType != "" {
			resp := new(dhutil.Envelope)
			if err := jsonutil.DecodeJSON([]byte(token), resp); err != nil {
				return nil, fmt.Errorf("error JSON-decoding file sink %s: %v", path, err)
			}

			dhPrivKeyFileRaw, ok := sink.Config["dh_priv"]
			if !ok {
				return nil, fmt.Errorf("path to Diffie-Hellman private key (field 'dh_priv') not " +
					"specified in 'config' stanza of file sink %s", path)
			}

			dhPrivKeyFile, ok := dhPrivKeyFileRaw.(string)
			if !ok {
				return nil, fmt.Errorf("'dh_priv' of file sink %s cannot be converted to string", path)
			}

			file, err := os.Open(dhPrivKeyFile)
			if err != nil {
				return nil, fmt.Errorf("error opening 'dh_priv' file %s: %v", dhPrivKeyFile, err)
			}

			pkInfo := new(PrivateKeyInfo)
			if err = jsonutil.DecodeJSONFromReader(file, pkInfo); err != nil {
				return nil, fmt.Errorf("error JSON-decoding file %s: %v", dhPrivKeyFile, err)
			}

			if pkInfo.Curve25519PrivateKey == "" {
				return nil, fmt.Errorf("field 'curve25519_private_key' of file %s is empty", dhPrivKeyFile)
			}

			dhPrivKey, err := base64.StdEncoding.DecodeString(pkInfo.Curve25519PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("error JSON-decoding 'curve25519_private_key' of file %s: %v", dhPrivKeyFile, err)
			}

			aesKey, err := dhutil.GenerateSharedKey(dhPrivKey, resp.Curve25519PublicKey)
			if err != nil {
				return nil, fmt.Errorf("error creating AES-GCM key: %v", err)
			}

			if len(aesKey) == 0 {
				return nil, errors.New("got empty AES key")
			}

			data, err := dhutil.DecryptAES(aesKey, resp.EncryptedPayload, resp.Nonce, []byte(sink.AAD))
			if err != nil {
				return nil, fmt.Errorf("error decrypting token: %v", err)
			}

			token = string(data)
		}

		// Secret is TTL-wrapped
		if sink.WrapTTL != 0 {
			wrapInfo := new(api.SecretWrapInfo)
			if err := jsonutil.DecodeJSON([]byte(token), wrapInfo); err != nil {
				return nil, fmt.Errorf("error JSON-decoding TTL-wrapped secret: %v", err)
			}

			client.SetToken(wrapInfo.Token)
			secret, err := client.Logical().Unwrap("")
			if err != nil {
				return nil, fmt.Errorf("error unwrapping token: %v", err)
			}

			token, err = secret.TokenID()
			if err != nil {
				return nil, fmt.Errorf("no token found: %v", err)
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
	return tokens, nil
}

