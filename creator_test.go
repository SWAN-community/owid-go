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
	"crypto/rand"
	"fmt"
	"testing"
)

// TestCreatorCreateOWID verifies that a created OWID is signed and contains the
// payload, the current version and the domain of the creator.
func TestCreatorCreateOWID(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.Create([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	if o.version != owidVersion3 {
		t.Errorf("expected version '%d', found '%d'", owidVersion3, o.version)
	}
	if o.domain != c.Domain() {
		t.Errorf("expected domain '%s', found '%s'", c.Domain(), o.domain)
	}
	if bytes.Equal(o.payload, []byte(testPayload)) == false {
		t.Error("payload does not match the input")
	}
	// Creation signs. There is no longer a moment at which an unsigned OWID
	// exists for a caller to hold, which is the point of routing creation
	// through the creator rather than exposing an unsigned builder.
	if len(o.signature) != signatureLength {
		t.Errorf(
			"a created OWID should carry a '%d' byte signature, found '%d'",
			signatureLength,
			len(o.signature))
	}
}

// TestCreatorSign verifies that signing an OWID sets the signature to the
// expected length.
func TestCreatorSign(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.Create([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	err = c.signOwid(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.signature) != signatureLength {
		t.Errorf(
			"expected signature length '%d', found '%d'",
			signatureLength,
			len(o.signature))
	}
}

// TestCreatorCreateOWIDandSign verifies the combined create and sign method
// produces an OWID that passes verification by the same creator.
func TestCreatorCreateOWIDandSign(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	if o.domain != c.Domain() {
		t.Errorf("expected domain '%s', found '%s'", c.Domain(), o.domain)
	}
	v, err := c.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("OWID did not pass verification"))
	}
}

// TestCreatorVerify verifies the creator confirms an OWID signed with its
// own keys.
func TestCreatorVerify(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("OWID did not pass verification"))
	}
}

// TestCreatorVerifyWrongKey verifies that an OWID signed by one creator does
// not pass verification with the keys of another creator for the same
// domain.
func TestCreatorVerifyWrongKey(t *testing.T) {
	a, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := a.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	v, err := b.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != false {
		t.Fatal(fmt.Errorf("wrong public key should not verify the OWID"))
	}
}

// TestCreatorEmptyPayload verifies that an OWID with a nil payload can be
// signed, serialized and verified.
func TestCreatorEmptyPayload(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign(nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("empty payload OWID did not pass verification"))
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromBase64(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.payload) != 0 {
		t.Errorf("expected empty payload, found '%d' bytes", len(n.payload))
	}
	v, err = n.VerifyWithPublicKey(c.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("decoded empty payload OWID did not pass " +
			"verification"))
	}
}

// TestCreatorLargePayload verifies that an OWID with a 10,000 byte random
// payload can be signed, serialized and verified.
func TestCreatorLargePayload(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 10000)
	_, err = rand.Read(p)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("large payload OWID did not pass verification"))
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromBase64(a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n.payload, p) == false {
		t.Error("decoded payload does not match the input")
	}
	v, err = n.VerifyWithPublicKey(c.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal(fmt.Errorf("decoded large payload OWID did not pass " +
			"verification"))
	}
}

// TestCreatorBatch verifies that 10 distinct OWIDs can be created and each
// passes verification.
func TestCreatorBatch(t *testing.T) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		o, err := c.CreateOWIDandSign([]byte(fmt.Sprintf("payload %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		v, err := c.Verify(o)
		if err != nil {
			t.Fatal(err)
		}
		if v != true {
			t.Fatalf("OWID '%d' did not pass verification", i)
		}
		seen[o.AsString()] = true
	}
	if len(seen) != 10 {
		t.Errorf("expected 10 distinct OWIDs, found '%d'", len(seen))
	}
}
