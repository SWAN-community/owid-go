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
	"net/url"
	"strings"
	"testing"
)

func TestOWIDVerify(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := o.VerifyWithPublicKey(c.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("OWID did not pass verification"))
	}
}

func TestOWIDBase64(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
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
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
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
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	// Drop the last character that carries data rather than the last
	// character of the string, because the string may end in padding and
	// padding is optional, so removing it is not corruption.
	significant := strings.TrimRight(a, "=")
	_, err = FromBase64(significant[:len(significant)-1])
	if err == nil {
		t.Fatal(fmt.Errorf("corrupt base 64 string should result in error"))
	}
}

func TestOWIDBase64CorruptMiss(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
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
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for i < len(a) {
		err = corrupt(c, a, i)
		if err == nil {
			t.Fatal(fmt.Errorf("corrupt byte array should result in error"))
		}
		i++
	}
}

// TestOWIDModifiedDomain verifies that changing the domain after signing
// causes verification to fail.
func TestOWIDModifiedDomain(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	o.domain = "different.com"
	v, err := o.VerifyWithPublicKey(c.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatal(fmt.Errorf("modified domain should not pass verification"))
	}
}

// TestOWIDChain verifies that an OWID signed with other OWIDs passes
// verification when the same others are provided, and fails when they are
// omitted, reordered or different.
func TestOWIDChain(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.CreateOWIDandSign([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.CreateOWIDandSign([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload), first, second)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the same others in the same order.
	v, err := c.Verify(o, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("chained OWID did not pass verification"))
	}
	v, err = o.VerifyWithPublicKey(c.publicKey, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("chained OWID did not pass verification with " +
			"public key"))
	}

	// Verify fails when the others are omitted.
	v, err = c.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatal(fmt.Errorf("chained OWID should not verify without others"))
	}

	// Verify fails when the others are in a different order.
	v, err = c.Verify(o, second, first)
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatal(fmt.Errorf("chained OWID should not verify with others in " +
			"a different order"))
	}

	// Verify fails when a different other is provided.
	other, err := c.CreateOWIDandSign([]byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	v, err = c.Verify(o, first, other)
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatal(fmt.Errorf("chained OWID should not verify with different " +
			"others"))
	}
}

// TestOWIDQueryFormRoundTrip verifies that an OWID added to a query string
// with ToQuery can be read back with FromForm.
func TestOWIDQueryFormRoundTrip(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	err = o.ToQuery("owid", &q)
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromForm(&q, "owid")
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(n) == false {
		t.Error("query and form round trip failed")
	}
	_, err = FromForm(&q, "missing")
	if err == nil {
		t.Fatal(fmt.Errorf("missing form key should result in error"))
	}
}

// TestOWIDVersion1 verifies that a buffer constructed in the version 1
// format can be read with FromBuffer. The version 1 date resolution is one
// day.
func TestOWIDVersion1(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromBuffer(toVersionBuffer(t, o, owidVersion1))
	if err != nil {
		t.Fatal(err)
	}
	if n.version != owidVersion1 {
		t.Errorf("expected version '%d', found '%d'", owidVersion1, n.version)
	}
	compareVersionFields(t, o, n)
	testCompareDate(t, n.date, o.date)
}

// TestOWIDVersion2 verifies that a buffer constructed in the version 2
// format can be read with FromBuffer. The version 2 date resolution is one
// minute.
func TestOWIDVersion2(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromBuffer(toVersionBuffer(t, o, owidVersion2))
	if err != nil {
		t.Fatal(err)
	}
	if n.version != owidVersion2 {
		t.Errorf("expected version '%d', found '%d'", owidVersion2, n.version)
	}
	compareVersionFields(t, o, n)
	if n.date.Equal(o.date) == false {
		t.Errorf("expected date '%v', found '%v'", o.date, n.date)
	}
}

// TestOWIDVersionUnsupported verifies that a buffer with an unsupported
// version byte results in an error from FromBuffer.
func TestOWIDVersionUnsupported(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := newOWID(c)
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	a[0] = 99
	_, err = FromByteArray(a)
	if err == nil {
		t.Fatal(fmt.Errorf("unsupported version should result in error"))
	}
}

// toVersionBuffer writes the fields of the OWID to a buffer using the format
// for the version provided.
func toVersionBuffer(t *testing.T, o *OWID, v byte) *bytes.Buffer {
	var b bytes.Buffer
	err := writeByte(&b, v)
	if err != nil {
		t.Fatal(err)
	}
	err = writeString(&b, o.domain)
	if err != nil {
		t.Fatal(err)
	}
	err = writeDate(&b, o.date, v)
	if err != nil {
		t.Fatal(err)
	}
	err = writeByteArray(&b, o.payload)
	if err != nil {
		t.Fatal(err)
	}
	err = writeSignature(&b, o.signature)
	if err != nil {
		t.Fatal(err)
	}
	return &b
}

// compareVersionFields checks the fields that are common to all versions.
func compareVersionFields(t *testing.T, o *OWID, n *OWID) {
	if n.domain != o.domain {
		t.Errorf("expected domain '%s', found '%s'", o.domain, n.domain)
	}
	if bytes.Equal(n.payload, o.payload) == false {
		t.Error("payload does not match the input")
	}
	if bytes.Equal(n.signature, o.signature) == false {
		t.Error("signature does not match the input")
	}
}

func newOWID(creator *Creator) (*OWID, error) {
	c, err := NewCryptoSignOnly(creator.privateKey)
	if err != nil {
		return nil, err
	}
	payload := []byte(testPayload)
	o, err := newOwid(testDomain, testDate, payload)
	if err != nil {
		return nil, err
	}
	o.sign(c, nil)
	return o, nil
}

func corrupt(creator *Creator, a []byte, i int) error {
	a[i] = a[i] + 1
	n, err := FromByteArray(a)
	if err != nil {
		return err
	}
	_, err = n.VerifyWithPublicKey(creator.publicKey)
	return err
}

func (o *OWID) compare(other *OWID) bool {
	return o.version == other.version &&
		o.date == other.date &&
		bytes.Equal(o.signature, other.signature) &&
		bytes.Equal(o.payload, other.payload)
}
