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
	"errors"
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
