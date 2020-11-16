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

func newOwid() (*OWID, *Creator, error) {
	cry, err := NewCryptoSignOnly(testPrivateKey)
	if err != nil {
		return nil, nil, err
	}

	c := Creator{
		testDomain,
		testPrivateKey,
		testPublicKey,
		testOrgName}

	payload := []byte(testPayload)

	signature, err := cry.Sign(testDate, payload)
	if err != nil {
		return nil, nil, err
	}

	o, err := NewOwid(testDomain, signature, testDate, payload)
	if err != nil {
		return nil, nil, err
	}

	return o, &c, nil
}

func TestOwidEncode(t *testing.T) {
	o, _, err := newOwid()
	if err != nil {
		t.Fatal(err)
	}

	owidJSON, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}

	expected := testJSON
	if owidJSON != expected {
		t.Errorf("encode returned unexpected json: got %v want %v",
			owidJSON, expected)
	}
}

// func TestOwidDecode(t *testing.T) {
// 	owidJSON := testJSON

// 	o, err := Decode(owidJSON)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	expectedDomain := testDomain
// 	if o.Domain != expectedDomain {
// 		t.Errorf("decode returned unexpected value for domain, expected '%v' "+
// 			"got '%v'", expectedDomain, o.Domain)
// 	}

// 	expectedDate := testDate
// 	if o.Date != expectedDate {
// 		t.Errorf("decode returned unexpected value for date, expected '%v' "+
// 			"got '%v'", expectedDate, o.Date)
// 	}

// 	expectedPayload := testPayload
// 	if string(o.Payload) != expectedPayload {
// 		t.Errorf("decode returned unexpected value for payload, expected '%v' "+
// 			"got '%v'", expectedPayload, string(o.Payload))
// 	}
// }

func TestOwidEncodeAsBase64(t *testing.T) {
	o, _, err := newOwid()
	if err != nil {
		t.Fatal(err)
	}

	owid, err := o.EncodeAsBase64()
	if err != nil {
		t.Fatal(err)
	}

	expected := testOwid
	if owid != expected {
		t.Errorf("encode returned unexpected owid: got %v want %v", owid, expected)
	}
}

func TestOwidDecodeAsBase64(t *testing.T) {
	owid := testOwid

	o, err := DecodeFromBase64(owid)
	if err != nil {
		t.Fatal(err)
	}

	expectedDomain := testDomain
	if o.Domain != expectedDomain {
		t.Errorf("decode returned unexpected value for domain, expected '%v' "+
			"got '%v'", expectedDomain, o.Domain)
	}

	expectedDate := testDate
	if o.Date != expectedDate {
		t.Errorf("decode returned unexpected value for date, expected '%v' "+
			"got '%v'", expectedDate, o.Date)
	}

	expectedPayload := testPayload
	if string(o.Payload) != expectedPayload {
		t.Errorf("decode returned unexpected value for payload, expected '%v' "+
			"got '%v'", expectedPayload, string(o.Payload))
	}
}
