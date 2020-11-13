/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited
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

// TODO Lots of unit tests to make sure the crypto functions work.

func newCrypto() (*Crypto, error) {
	cry, err := NewCrypto()
	if err != nil {
		return nil, err
	}

	return cry, nil
}

func TestNewCrypto(t *testing.T) {
	cry, err := newCrypto()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := cry.privateKeyToPemString()
	publicKey := cry.publicKeyToPemString()

	_, err = NewCryptoSignOnly(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewCryptoVerifyOnly(publicKey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignOnly(t *testing.T) {
	cry, err := NewCryptoSignOnly(testPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(testPayload)

	_, err = cry.Sign(testDate, payload)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyOnly(t *testing.T) {
	cry, err := NewCryptoVerifyOnly(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	verified, err := cry.Verify(testOwid)
	if err != nil {
		t.Fatal(err)
	}

	if verified == false {
		t.Errorf("signature was invalid")
	}
}
