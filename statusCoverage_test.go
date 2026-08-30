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

// Every failure condition gets a test, which James Rosewell asked for across
// all the ports. Where a status cannot be reached in Go the reason is recorded
// here and on the status itself, so a gap is a stated decision rather than
// something nobody noticed.
//
// The last test in this file walks both vocabularies and fails if a member is
// neither exercised nor named unreachable, so a status cannot be added later
// and left silently untested.

// reachedParse records the statuses a test in this file actually produced.
var reachedParse = map[ParseStatus]bool{}

// assertParse checks the whole of what the contract promises on failure and
// notes which status was reached.
func assertParse(t *testing.T, b []byte, want ParseStatus) {
	t.Helper()
	o, err := FromByteArray(b)
	if o != nil {
		t.Error("no value should be handed back on failure")
	}
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a ParseError, got %v", err)
	}
	if pe.Status != want {
		t.Errorf("expected %s, got %s", want, pe.Status)
	}
	reachedParse[pe.Status] = true
}

func TestEveryParseFailureIsReported(t *testing.T) {
	c := contractCreator(t)
	o, err := c.Create([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	reachedParse[Parsed] = true

	t.Run("MissingInput", func(t *testing.T) {
		assertParse(t, []byte{}, MissingInput)
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		_, err := FromBase64("not base 64 at all!!")
		var pe *ParseError
		if !errors.As(err, &pe) || pe.Status != InvalidBase64 {
			t.Fatalf("expected InvalidBase64, got %v", err)
		}
		reachedParse[InvalidBase64] = true
	})

	t.Run("UnsupportedVersion", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[0] = 9
		assertParse(t, bad, UnsupportedVersion)
	})

	t.Run("the absent marker is not an OWID", func(t *testing.T) {
		// Version 0 stands for an absent node inside a stream. It carries no
		// domain, date, payload or signature, so it can never verify, and
		// letting one through would be the single case of an instance with no
		// signature reaching a caller.
		assertParse(t, []byte{0}, UnsupportedVersion)
	})

	t.Run("UnexpectedEnd", func(t *testing.T) {
		// Data that stops inside a field, before the declared length is even
		// read. Distinct from a declaration disagreeing with data that is here.
		assertParse(t, good[:3], UnexpectedEnd)
	})

	t.Run("InvalidDomainEncoding", func(t *testing.T) {
		// A domain that never terminates within the published maximum.
		bad := append([]byte{owidVersion3}, make([]byte, 300)...)
		for i := 1; i < len(bad); i++ {
			bad[i] = 'a'
		}
		assertParse(t, bad, InvalidDomainEncoding)
	})

	t.Run("ByteCountMismatch, one byte too many", func(t *testing.T) {
		assertParse(t, append(append([]byte(nil), good...), 0), ByteCountMismatch)
	})

	t.Run("ByteCountMismatch, signature one byte short", func(t *testing.T) {
		// The declared payload cannot leave exactly the signature the version
		// requires, which is the finding whichever way the bytes fall short.
		assertParse(t, good[:len(good)-1], ByteCountMismatch)
	})
}

// reachedSignature records the signature statuses a test produced.
var reachedSignature = map[SignatureStatus]bool{}

func TestEverySignatureOutcomeIsReported(t *testing.T) {
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
	public, err := crypto.publicKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}

	record := func(got, want SignatureStatus) {
		t.Helper()
		if got != want {
			t.Errorf("expected %s, got %s", want, got)
		}
		reachedSignature[got] = true
	}

	t.Run("SignatureValid", func(t *testing.T) {
		record(o.SignatureStatusWithPublicKey(public), SignatureValid)
	})

	t.Run("SignatureInvalid only when it really does not match", func(t *testing.T) {
		b, err := o.AsByteArray()
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)-1] ^= 0xFF
		tampered, err := FromByteArray(b)
		if err != nil {
			t.Fatal(err)
		}
		record(tampered.SignatureStatusWithPublicKey(public), SignatureInvalid)
	})

	t.Run("KeyUnavailable is not a forgery", func(t *testing.T) {
		record(o.SignatureStatusWithPublicKey(""), KeyUnavailable)
	})

	t.Run("InvalidKey is not a forgery", func(t *testing.T) {
		// This is the case that happened. On 30 August 2026 the key end points
		// served PEM a strict parser rejects, and reporting it as a forgery
		// would have read as an attack rather than the outage it was.
		record(
			o.SignatureStatusWithPublicKey(
				"-----BEGIN PUBLIC KEY-----\nnot base 64\n-----END PUBLIC KEY-----"),
			InvalidKey)
	})

	t.Run("InvalidSignatureLength", func(t *testing.T) {
		// A parse only succeeds when the signature is exactly the required
		// length, so this covers an OWID reaching the check by another route.
		short := &OWID{
			version:   o.version,
			domain:    o.domain,
			date:      o.date,
			payload:   o.payload,
			signature: o.signature[:signatureLength-1],
		}
		record(short.SignatureStatusWithPublicKey(public), InvalidSignatureLength)
	})
}

// TestEveryStatusIsCoveredOrNamedUnreachable fails when a status is neither
// produced by a test above nor listed here as unreachable, so one cannot be
// added later and left silently untested.
func TestEveryStatusIsCoveredOrNamedUnreachable(t *testing.T) {
	// Kept as guards rather than removed, because the arithmetic they back up
	// could change, and because a status that must never be reported as a
	// forgery is worth keeping even when nothing can produce it today.
	unreachableParse := map[ParseStatus]string{
		ImplementationCapacityExceeded: "a Go slice index cannot exceed the " +
			"declaration the count check already refused",
		MalformedEnvelope: "no path while the byte count rule holds; a " +
			"backstop against a future change to that arithmetic",
	}
	// The Go signature vocabulary has no capacity member: nothing here can
	// exceed what the runtime holds without the parse having refused it first.
	unreachableSignature := map[SignatureStatus]string{
		VerificationError: "needs the provider to fail on inputs that are " +
			"themselves fine",
	}

	all := []ParseStatus{
		Parsed, MissingInput, InvalidBase64, UnsupportedVersion, UnexpectedEnd,
		InvalidDomainEncoding, ByteCountMismatch,
		ImplementationCapacityExceeded, MalformedEnvelope,
	}
	for _, s := range all {
		if reachedParse[s] {
			continue
		}
		if _, named := unreachableParse[s]; named {
			continue
		}
		t.Errorf(
			"parse status %s is neither tested nor named unreachable", s)
	}

	allSig := []SignatureStatus{
		SignatureValid, SignatureInvalid, InvalidSignatureLength,
		KeyUnavailable, InvalidKey, VerificationError,
	}
	for _, s := range allSig {
		if reachedSignature[s] {
			continue
		}
		if _, named := unreachableSignature[s]; named {
			continue
		}
		t.Errorf(
			"signature status %s is neither tested nor named unreachable", s)
	}
}
