// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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
	"github.com/morningconsult/docker-credential-vault-login/vault-login/config"
	"sync"
	"time"
)

const GracePeriodSeconds int64 = 600 // 10 minutes

type CachedToken struct {
	// Token is the cached Vault token
	Token string `json:"token,omitempty" mapstructure:"token"`

	// Expiration is the date and time at which this token expires
	// (represented as a Unix timestamp)
	Expiration int64 `json:"expiration" mapstructure:"expiration"`

	// Renewable is whether the token can be renewed
	Renewable bool `json:"renewable" mapstructure:"renewable"`

	// Method is the authentication method by which the token was
	// obtained (specified in the config.json file)
	method config.VaultAuthMethod `json:"-"`

	// Host is the host of the Vault server from which this token was
	// obtained
	host string `json:"-"`

	mutex sync.RWMutex
}

// Expired returns true if the token's expiration
// timestamp is in the past.
func (t *CachedToken) Expired() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return time.Now().After(time.Unix(t.Expiration, 0))
}

// EligibleForRenewal returns true if the token is
// renewable and the current time is within the grace
// period. The grace period is the period of time
// GracePeriodSeconds seconds before the expiration
// timestamp.
func (t *CachedToken) EligibleForRenewal() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	now := time.Now()
	expiration := time.Unix(t.Expiration, 0)
	windowStart := expiration.Add(time.Second * time.Duration(-1*GracePeriodSeconds))
	return t.Renewable && now.Before(expiration) && now.After(windowStart)
}

func (t *CachedToken) ToMap() map[string]interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return map[string]interface{}{
		"token":      t.Token,
		"expiration": t.Expiration,
		"renewable":  t.Renewable,
	}
}

func (t *CachedToken) TokenID() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.Token
}

func (t *CachedToken) ExpirationTS() int64 {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.Expiration
}

func (t *CachedToken) SetAuthMethod(method config.VaultAuthMethod) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.method = method
}

func (t *CachedToken) AuthMethod() config.VaultAuthMethod {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.method
}

func (t *CachedToken) SetVaultHost(host string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.host = host
}

func (t *CachedToken) VaultHost() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return t.host
}
