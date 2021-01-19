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
	"testing"
)

func newCrypto() (*Crypto, error) {
	c, err := NewCrypto()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func TestCrypto(t *testing.T) {
	c, err := newCrypto()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := c.privateKeyToPemString()
	publicKey := c.publicKeyToPemString()
	s, err := NewCryptoSignOnly(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewCryptoVerifyOnly(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.SignByteArray([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.VerifyByteArray([]byte(testPayload), a)
	if err != nil {
		t.Fatal(err)
	}
	if b != true {
		t.Errorf("signature was invalid")
	}
}
