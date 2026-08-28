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
	"encoding/binary"
	"runtime"
	"testing"
)

// The payload length field of an OWID is whatever the sender declared, so
// parsing must check it against the bytes present before sizing anything by
// it. These tests prove that a declared length that does not leave exactly
// the signature after the payload is refused, that refusing it costs no
// allocation sized by the declared number, and that a correctly sized
// envelope still parses. The 64 byte signature is the fixed tail every valid
// OWID ends with.

// payloadLengthPayload is the payload used by the envelopes below, 37 bytes
// of 0x5A.
var payloadLengthPayload = payloadLengthFilled(37, 0x5A)

// payloadLengthSignature is a 64 byte stand in for a signature. The tests
// here are about the shape of the envelope, not the cryptography, so the
// bytes do not need to verify.
var payloadLengthSignature = payloadLengthFilled(signatureLength, 0x99)

// payloadLengthEnvelope builds a version 3 envelope, being the version byte,
// the domain with its terminator, four minute bytes, the declared payload
// length, the payload bytes given and the signature bytes given, so a test
// can make the declared length and the bytes present disagree.
func payloadLengthEnvelope(
	declared uint32,
	payload []byte,
	signature []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(owidVersion3)
	b.WriteString("51d.es")
	b.WriteByte(0)
	minutes := make([]byte, 4)
	binary.LittleEndian.PutUint32(minutes, 1000)
	b.Write(minutes)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, declared)
	b.Write(length)
	b.Write(payload)
	b.Write(signature)
	return b.Bytes()
}

// payloadLengthFilled returns a byte slice of the length given where every
// byte holds the value given.
func payloadLengthFilled(length int, value byte) []byte {
	v := make([]byte, length)
	for i := range v {
		v[i] = value
	}
	return v
}

// TestPayloadLengthMatchesParses proves that when the declared length
// matches the bytes present and the signature is the last 64 bytes the
// envelope parses to the same domain, payload and signature.
func TestPayloadLengthMatchesParses(t *testing.T) {
	e := payloadLengthEnvelope(
		uint32(len(payloadLengthPayload)),
		payloadLengthPayload,
		payloadLengthSignature)
	o, err := FromByteArray(e)
	if err != nil {
		t.Fatal(err)
	}
	if o.Domain != "51d.es" {
		t.Errorf("expected domain '51d.es', found '%s'", o.Domain)
	}
	if bytes.Equal(o.Payload, payloadLengthPayload) == false {
		t.Error("payload does not match the input")
	}
	if bytes.Equal(o.Signature, payloadLengthSignature) == false {
		t.Error("signature does not match the input")
	}
}

// TestPayloadLengthMatchingOneMebibyteParses proves that a payload materially
// larger than an ordinary identifier remains valid when its declaration and
// bytes agree. Application policy is separate from format validity.
func TestPayloadLengthMatchingOneMebibyteParses(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 1024*1024)
	e := payloadLengthEnvelope(
		uint32(len(payload)), payload, payloadLengthSignature)

	o, err := FromByteArray(e)
	if err != nil {
		t.Fatalf("matching payload should parse: %v", err)
	}
	if bytes.Equal(o.Payload, payload) == false {
		t.Fatal("payload does not match the input")
	}
}

// TestPayloadLengthLibraryOutputParses proves that an OWID created and
// signed by the library's own signing path still parses, so the check
// agrees with what the library itself produces.
func TestPayloadLengthLibraryOutputParses(t *testing.T) {
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
	n, err := FromByteArray(a)
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(n) == false {
		t.Error("library output did not round trip")
	}
}

// TestPayloadLengthOffByOneRefused proves that a declared length one more
// or one fewer than the bytes present is refused, because either leaves
// something other than exactly the signature at the end.
func TestPayloadLengthOffByOneRefused(t *testing.T) {
	l := len(payloadLengthPayload)
	for _, declared := range []int{l - 1, l + 1} {
		e := payloadLengthEnvelope(
			uint32(declared),
			payloadLengthPayload,
			payloadLengthSignature)
		_, err := FromByteArray(e)
		if err == nil {
			t.Errorf("declared length '%d' should be refused", declared)
		}
	}
}

// TestPayloadLengthTrailingByteRefused proves that a byte after the
// signature is refused, because the signature must be the end of the
// envelope.
func TestPayloadLengthTrailingByteRefused(t *testing.T) {
	e := payloadLengthEnvelope(
		uint32(len(payloadLengthPayload)),
		payloadLengthPayload,
		payloadLengthSignature)
	e = append(e, 0)
	_, err := FromByteArray(e)
	if err == nil {
		t.Error("a trailing byte after the signature should be refused")
	}
}

// TestPayloadLengthShortSignatureRefused proves that a signature of 63
// bytes is refused. The declared payload length is right for the payload,
// but the bytes after it are fewer than a signature.
func TestPayloadLengthShortSignatureRefused(t *testing.T) {
	e := payloadLengthEnvelope(
		uint32(len(payloadLengthPayload)),
		payloadLengthPayload,
		payloadLengthFilled(signatureLength-1, 0x99))
	_, err := FromByteArray(e)
	if err == nil {
		t.Error("a signature shorter than 64 bytes should be refused")
	}
}

// TestPayloadLengthMismatchedLargeDeclarationRefusedWithoutAllocating proves
// that a large declaration whose payload bytes are absent is refused without
// an allocation sized by the declared number. The envelope is a few dozen
// bytes while declaring 64 MiB, then 2 GiB, then the largest value the field
// can hold. The numeric values remain valid when the matching payload is
// present, while each malformed refusal here allocates under 64 KiB.
// Allocation is measured as the change in total bytes reported by the
// runtime.
func TestPayloadLengthMismatchedLargeDeclarationRefusedWithoutAllocating(
	t *testing.T,
) {
	for _, declared := range []uint32{
		64 * 1024 * 1024,
		0x7FFFFFFF,
		0xFFFFFFFF,
	} {
		e := payloadLengthEnvelope(declared, nil, nil)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := FromByteArray(e)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Errorf("declared length '%d' should be refused", declared)
		}
		allocated := after.TotalAlloc - before.TotalAlloc
		if allocated >= 64*1024 {
			t.Errorf(
				"declared length '%d' allocated '%d' bytes",
				declared,
				allocated)
		}
	}
}

// TestPayloadLengthEmptyPayloadParses proves that an empty payload, being a
// declared length of zero followed by the 64 byte signature, parses.
func TestPayloadLengthEmptyPayloadParses(t *testing.T) {
	e := payloadLengthEnvelope(0, nil, payloadLengthSignature)
	o, err := FromByteArray(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Payload) != 0 {
		t.Errorf("expected an empty payload, found '%d' bytes", len(o.Payload))
	}
	if bytes.Equal(o.Signature, payloadLengthSignature) == false {
		t.Error("signature does not match the input")
	}
}
