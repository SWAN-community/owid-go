/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

package owid

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SWAN-community/common-go"
)

func TestKeys(t *testing.T) {
	t.Run("fresh", func(t *testing.T) {
		testKeys(t, testKeysCreate(t, common.IoDateBase))
	})
	t.Run("copied", func(t *testing.T) {
		testKeys(t, testKeysCopy(t, testKeysCreate(t, common.IoDateBase)))
	})
	t.Run("equal", func(t *testing.T) {
		b := time.Now()
		k := testKeysCreate(t, b.UTC())
		c := *k
		if !k.equal(&c) {
			t.Fatal("keys should be equal")
		}
		c.Created = b
		if !k.equal(&c) {
			t.Fatal("keys should be equal")
		}
	})
}

// testKeysCreate creates a set of new keys for testing.
func testKeysCreate(t *testing.T, d time.Time) *Keys {
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := c.privateKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := c.publicKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}
	return &Keys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Created:    d}
}

// testCopy copies the keys to a new structure using json marshall methods.
// Needed to verify that the unmarshalled structure passes the same tests as
// a freshly created instance.
func testKeysCopy(t *testing.T, source *Keys) *Keys {
	var c Keys
	j, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(j, &c)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// testKeys signs and verifies data with the keys provided.
func testKeys(t *testing.T, k *Keys) {
	var data = []byte("A")
	s, err := k.NewCryptoSignOnly()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignByteArray(data)
	if err != nil {
		t.Fatal(err)
	}
	v, err := k.NewCryptoVerifyOnly()
	if err != nil {
		t.Fatal(err)
	}
	a, err := v.VerifyByteArray(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !a {
		t.Fatal("Verification should pass")
	}
}
