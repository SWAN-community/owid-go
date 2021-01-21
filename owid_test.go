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
	"bytes"
	"fmt"
	"testing"
)

func newOWID() (*OWID, error) {
	c, err := NewCryptoSignOnly(testPrivateKey)
	if err != nil {
		return nil, err
	}
	payload := []byte(testPayload)
	o, err := NewOwid(testDomain, testDate, payload)
	if err != nil {
		return nil, err
	}
	o.Sign(c, nil)
	return o, nil
}

func TestOWIDVerify(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	v, err := o.VerifyWithPublicKey(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("OWID did not pass verification"))
	}
}

func TestOWIDBase64(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromBase64(a)
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(b) == false {
		t.Error("encode and decode failed")
	}
}

func TestOWIDString(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromBase64(o.AsString())
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(b) == false {
		t.Error("encode and decode failed")
	}
}

func TestOWIDBase64CorruptShort(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromBase64(a[:len(a)-1])
	if err == nil {
		t.Fatal(fmt.Errorf("corrupt base 64 string should result in error"))
	}
}

func TestOWIDBase64CorruptMiss(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromBase64(a[1:])
	if err == nil {
		t.Fatal(fmt.Errorf("corrupt base 64 string should result in error"))
	}
}

func TestOWIDByteArrayCorruptReplace(t *testing.T) {
	o, err := newOWID()
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for i < len(a) {
		err = corrupt(a, i)
		if err == nil {
			t.Fatal(fmt.Errorf("corrupt byte array should result in error"))
		}
		i++
	}
}

func corrupt(a []byte, i int) error {
	a[i] = a[i] + 1
	n, err := FromByteArray(a)
	if err != nil {
		return err
	}
	_, err = n.VerifyWithPublicKey(testPublicKey)
	return err
}

func (o *OWID) compare(other *OWID) bool {
	return o.Version == other.Version &&
		o.Date == other.Date &&
		bytes.Equal(o.Signature, other.Signature) &&
		bytes.Equal(o.Payload, other.Payload)
}
