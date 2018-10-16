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
	"testing"
	"time"
)

func TestExpired(t *testing.T) {
	cases := []struct {
		name    string
		delta   int
		expired bool
	}{
		{
			"expired",
			-3600,
			true,
		},
		{
			"not-expired",
			3600,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := &CachedToken{
				Token:      "",
				Expiration: time.Now().Add(time.Second * time.Duration(tc.delta)).Unix(),
			}

			if tc.expired && !token.Expired() {
				t.Fatal("token should be expired")
			}

			if !tc.expired && token.Expired() {
				t.Fatal("token should not be expired")
			}
		})
	}
}

func TestEligibleForRenewal(t *testing.T) {
	tsWithinGracePeriod := time.Now().Add(time.Duration(GracePeriodSeconds/2) * time.Second).Unix()
	expired := time.Now().Add(-100 * time.Second).Unix()
	cases := []struct {
		name       string
		expiration int64
		renewable  bool
		expected   bool
	}{
		{
			"renewable",
			tsWithinGracePeriod,
			true,
			true,
		},
		{
			"not-renewable",
			tsWithinGracePeriod,
			false,
			false,
		},
		{
			"renewable-but-expired",
			expired,
			true,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token := &CachedToken{
				Token:      "",
				Expiration: tc.expiration,
				Renewable:  tc.renewable,
			}

			if tc.expected && !token.EligibleForRenewal() {
				t.Fatal("token should be eligible for renewal")
			}

			if !tc.expected && token.EligibleForRenewal() {
				t.Fatal("token should not be eligible for renewal")
			}
		})
	}
}
