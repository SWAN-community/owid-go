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
	"testing"
)

// contractCreator returns a creator for the contract tests.
func contractCreator(t *testing.T) *Creator {
	t.Helper()
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCreator(testDomain, crypto)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// assertStatus checks that reading the bytes failed for the stated reason and
// returned no value, which is the whole of what the contract promises on
// failure.
func assertStatus(t *testing.T, b []byte, want ParseStatus) {
	t.Helper()
	o, err := FromByteArray(b)
	if err == nil {
		t.Fatalf("expected %s, but the bytes parsed", want)
	}
	if o != nil {
		t.Error("no value should be returned on failure")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a ParseError, got %T", err)
	}
	if pe.Status != want {
		t.Errorf("expected %s, got %s", want, pe.Status)
	}
}

// TestParseReportsWhyRatherThanJustFailing covers the reasons a caller may
// need to tell apart. Before this vocabulary a caller could see that a parse
// failed but not why, short of matching on message text.
func TestParseReportsWhyRatherThanJustFailing(t *testing.T) {
	c := contractCreator(t)
	o, err := c.Create([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("nothing supplied", func(t *testing.T) {
		if _, err := FromBase64(""); err == nil {
			t.Fatal("an empty string is not an OWID")
		} else {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Status != MissingInput {
				t.Errorf("expected MissingInput, got %v", err)
			}
		}
	})

	t.Run("not base 64", func(t *testing.T) {
		if _, err := FromBase64("not base 64 at all!!"); err == nil {
			t.Fatal("should be refused")
		} else {
			var pe *ParseError
			if !errors.As(err, &pe) || pe.Status != InvalidBase64 {
				t.Errorf("expected InvalidBase64, got %v", err)
			}
		}
	})

	t.Run("unknown version", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 9
		assertStatus(t, bad, UnsupportedVersion)
	})

	t.Run("trailing byte", func(t *testing.T) {
		assertStatus(t, append(append([]byte(nil), good...), 0), ByteCountMismatch)
	})

	t.Run("stops inside the envelope", func(t *testing.T) {
		assertStatus(t, good[:3], UnexpectedEnd)
	})
}

// TestEmptyAndLargePayloadsParse proves the format's limit is the wire
// format's. How large a payload an application will accept is that
// application's policy, not something this package decides for it.
func TestEmptyAndLargePayloadsParse(t *testing.T) {
	c := contractCreator(t)
	for name, payload := range map[string][]byte{
		"empty":      {},
		"one byte":   {7},
		"a megabyte": make([]byte, 1024*1024),
	} {
		t.Run(name, func(t *testing.T) {
			o, err := c.Create(payload)
			if err != nil {
				t.Fatal(err)
			}
			b, err := o.AsByteArray()
			if err != nil {
				t.Fatal(err)
			}
			back, err := FromByteArray(b)
			if err != nil {
				t.Fatalf("should parse: %v", err)
			}
			if !bytes.Equal(back.Payload(), payload) {
				t.Error("the payload should survive the round trip")
			}
		})
	}
}

// TestCreatedOwidIsAlwaysSigned is the boundary this package now keeps: an
// OWID cannot exist in an unsigned state, because an unsigned one is
// indistinguishable from a signed one to whatever handles it next, and the
// difference only surfaces later when a verification fails somewhere nobody is
// watching.
func TestCreatedOwidIsAlwaysSigned(t *testing.T) {
	c := contractCreator(t)

	o, err := c.Create([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	if len(o.Signature()) != signatureLength {
		t.Errorf(
			"a created OWID carries a '%d' byte signature, found '%d'",
			signatureLength,
			len(o.Signature()))
	}
}

// TestAccessorsReturnCopies proves that writing into what a caller was given
// cannot alter the OWID it came from. Without this, code could change a field
// the signature was computed over and hold something whose signature no longer
// describes it.
func TestAccessorsReturnCopies(t *testing.T) {
	c := contractCreator(t)
	o, err := c.Create([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	before := o.Payload()
	got := o.Payload()
	got[0] ^= 0xFF
	if !bytes.Equal(before, o.Payload()) {
		t.Error("writing into a returned payload must not alter the OWID")
	}

	sigBefore := o.Signature()
	sig := o.Signature()
	sig[0] ^= 0xFF
	if !bytes.Equal(sigBefore, o.Signature()) {
		t.Error("writing into a returned signature must not alter the OWID")
	}
}

// TestParsingIsNotVerification keeps the two questions apart. A structurally
// valid identifier whose signature does not match parses, and then fails
// verification, because whether the bytes are an OWID and whether they are
// genuine are different things with different answers.
func TestParsingIsNotVerification(t *testing.T) {
	crypto, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCreator(testDomain, crypto)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.Create([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xFF

	back, err := FromByteArray(b)
	if err != nil {
		t.Fatalf("flipping a signature byte leaves the envelope readable: %v", err)
	}

	valid, err := back.VerifyWithCrypto(crypto, nil)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Error("the signature no longer matches and must not verify")
	}
}
