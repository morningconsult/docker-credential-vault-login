package cache

import (
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"time"
)

const (
	GracePeriodSeconds int64 = 120 // 2 minutes
)

type CachedToken struct {
	// Token is the cached Vault token
	Token string `json:"token"`

	// Expiration is the date and time at which this
	// token expires (represented as a Unix timestamp)
	Expiration int64 `json:"expiration"`

	// Renewable is whether the token can be renewed
	Renewable bool `json:"renewable"`

	// AuthMethod is the authentication method by which
	// the token was obtained (specified in the
	// config.json file)
	AuthMethod config.VaultAuthMethod `json:"-"`
}

func (t *CachedToken) Expired() bool {
	return time.Now().After(time.Unix(t.Expiration, 0))
}

func (t *CachedToken) EligibleForRenewal() bool {
	now := time.Now()
	expiration := time.Unix(t.Expiration, 0)
	windowStart := expiration.Add(time.Second * time.Duration(-1*GracePeriodSeconds))
	return t.Renewable && now.Before(expiration) && now.After(windowStart)
}
