/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
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
	"errors"
	"net/url"
	"strings"
	"testing"
)

// TestReadmeCreateAndVerify runs the example the README shows, so that the
// documented way to use this package is compiled and executed rather than
// merely asserted.
//
// This exists because the README's previous example stopped compiling when
// creation moved behind the creator, and nothing noticed. A first draft of the
// replacement named a constructor that did not exist. Documentation that
// nothing runs drifts away from the code it describes, and a reader following
// it finds that out before we do.
func TestReadmeCreateAndVerify(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}

	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}

	o, err := creator.Create([]byte("example"))
	if err != nil {
		t.Fatal(err)
	}

	s, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}

	back, err := FromBase64(s)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := back.VerifyWithCrypto(crypto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("the round tripped OWID should verify with the same key")
	}
}

// TestReadmeChaining runs the chaining example from the README.
func TestReadmeChaining(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}

	root, err := creator.Create([]byte("root"))
	if err != nil {
		t.Fatal(err)
	}
	child, err := creator.Create([]byte("child"), root)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := child.VerifyWithCrypto(crypto, []*OWID{root})
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("the child should verify with the root as the other")
	}

	// And fails without it, which is what makes the chain mean anything.
	alone, err := child.VerifyWithCrypto(crypto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if alone {
		t.Error("the child should not verify without the root")
	}
}

// TestReadmeParseStatus runs the error handling example from the README, which
// is the reason the status vocabulary exists: a caller can tell a truncated
// envelope from a declaration that disagrees with the bytes present, without
// matching on message text.
func TestReadmeParseStatus(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}
	o, err := creator.Create([]byte("example"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}

	// One byte too many, so the declaration no longer matches what is here.
	_, err = FromByteArray(append(b, 0))
	if err == nil {
		t.Fatal("a trailing byte should be refused")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a ParseError, got %T", err)
	}
	if pe.Status != ByteCountMismatch {
		t.Errorf(
			"expected %s, got %s", ByteCountMismatch, pe.Status)
	}
}

// TestReadmeVerifyWithPublicKey runs the public key example from the README.
// The PEM a creator publishes for its own domain comes from
// SubjectPublicKeyInfo, which is the only exported way to reach it and is
// what the public-key end point serves, so the README says so.
func TestReadmeVerifyWithPublicKey(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}
	o, err := creator.Create([]byte("example"))
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPem, err := creator.SubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}

	valid, err := o.VerifyWithPublicKey(publicKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("the OWID should verify with the creator's published key")
	}
	if got := o.SignatureStatusWithPublicKey(publicKeyPem); got != SignatureValid {
		t.Errorf("expected %s, got %s", SignatureValid, got)
	}
}

// TestReadmeFramedReading runs the framed reading example from the README,
// being a buffer carrying one envelope after another where each read hands
// back what it read and leaves the rest, because what follows may be the next
// envelope rather than rubbish.
func TestReadmeFramedReading(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}

	var framed bytes.Buffer
	for _, payload := range []string{"first", "second"} {
		o, err := creator.Create([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if err := o.ToBuffer(&framed); err != nil {
			t.Fatal(err)
		}
	}

	var read []string
	for framed.Len() > 0 {
		o, err := FromBuffer(&framed)
		if err != nil {
			var pe *ParseError
			if errors.As(err, &pe) && pe.Status == AbsentNode {
				continue
			}
			t.Fatal(err)
		}
		read = append(read, o.PayloadAsString())
	}
	if len(read) != 2 || read[0] != "first" || read[1] != "second" {
		t.Errorf("expected both payloads in order, got %v", read)
	}
}

// TestReadmeAbsentNodeInARun runs the marker example from the README. The one
// byte is stepped over on a framed read, which is what lets the same loop
// reach the envelope after the gap, and the whole buffer read names the
// marker as well because the byte means the same thing wherever it appears.
func TestReadmeAbsentNodeInARun(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}
	o, err := creator.Create([]byte("after the gap"))
	if err != nil {
		t.Fatal(err)
	}

	var run bytes.Buffer
	if err := EmptyToBuffer(&run); err != nil {
		t.Fatal(err)
	}
	if err := o.ToBuffer(&run); err != nil {
		t.Fatal(err)
	}

	var read []string
	markers := 0
	for run.Len() > 0 {
		next, err := FromBuffer(&run)
		if err != nil {
			var pe *ParseError
			if errors.As(err, &pe) && pe.Status == AbsentNode {
				markers++
				continue
			}
			t.Fatal(err)
		}
		read = append(read, next.PayloadAsString())
	}
	if markers != 1 {
		t.Errorf("expected one marker, got %d", markers)
	}
	if len(read) != 1 || read[0] != "after the gap" {
		t.Errorf("expected the envelope after the gap, got %v", read)
	}

	// The whole buffer read has nothing to hand back and still names it.
	_, err = FromByteArray([]byte{0})
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Status != AbsentNode {
		t.Errorf("expected %s, got %v", AbsentNode, err)
	}
}

// TestReadmeBase64PaddingIsOptional holds the README to what this
// implementation accepts, being the standard alphabet with or without its
// trailing padding, as the other implementations do. A length one over a
// group of four encodes no whole byte, so that stays InvalidBase64.
func TestReadmeBase64PaddingIsOptional(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	creator, err := NewCreator("example.com", crypto)
	if err != nil {
		t.Fatal(err)
	}
	// A one byte payload leaves a length that needs padding.
	o, err := creator.Create([]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	s, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	stripped := strings.TrimRight(s, "=")
	if stripped == s {
		t.Fatal("this payload should produce padded base 64")
	}

	back, err := FromBase64(stripped)
	if err != nil {
		t.Fatalf("unpadded base 64 should parse, got %v", err)
	}
	if !bytes.Equal(back.Payload(), []byte{7}) {
		t.Errorf("payload changed on the unpadded route")
	}

	broken := stripped + "A"
	for len(broken)%4 != 1 {
		broken += "A"
	}
	_, err = FromBase64(broken)
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Status != InvalidBase64 {
		t.Errorf("expected %s, got %v", InvalidBase64, err)
	}
}

// TestReadmeFormReachesTheStatus holds the README to its claim that FromForm
// wraps a parse failure rather than turning it into text, so errors.As
// reaches the reason on that surface too.
func TestReadmeFormReachesTheStatus(t *testing.T) {
	q := url.Values{}
	q.Set("owid", "not base 64 at all!!")

	_, err := FromForm(&q, "owid")
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Status != InvalidBase64 {
		t.Errorf("expected %s, got %v", InvalidBase64, err)
	}

	_, err = FromForm(&q, "missing")
	if !errors.As(err, &pe) || pe.Status != MissingInput {
		t.Errorf("expected %s, got %v", MissingInput, err)
	}
}
