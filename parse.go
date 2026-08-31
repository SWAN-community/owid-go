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
	"encoding/binary"
	"math"
	"time"
)

// parseExact reads one complete OWID occupying the whole of b.
//
// The buffer is walked by index and every read is checked against what is
// left, so a malformed envelope is a comparison that fails rather than a
// panic recovered somewhere else. That matters because the data comes from
// outside: whoever sends it chooses how often this fails and how large each
// attempt is.
//
// This is the exact-buffer contract, so the envelope must end where the buffer
// does. Framed reading, where an envelope is followed by more data, stays with
// FromBuffer, which must not require the end of the stream because what
// follows may be the next envelope rather than rubbish.
func parseExact(b []byte) (*OWID, error) {
	o, _, err := parseFrom(b, true)
	return o, err
}

// parseFrom reads one envelope. When exact is false the envelope may be
// followed by more data, which is left for the caller, because in a stream
// what follows may be the next envelope rather than rubbish. It returns the
// number of bytes the envelope occupied.
func parseFrom(b []byte, exact bool) (*OWID, int, error) {
	if b == nil {
		return nil, 0, newParseError(MissingInput, "")
	}
	total := len(b)
	if total < 1 {
		// Nothing was supplied, which is not the same as data that stopped
		// part way through a field.
		return nil, 0, newParseError(MissingInput, "")
	}

	at := 1
	version := b[0]
	switch version {
	case owidVersion1, owidVersion2, owidVersion3:
	case owidVersionEmpty:
		// The marker stands for an absent node inside a stream. It is not an
		// OWID and no value is handed back, because it carries no signature
		// and can never verify. A framed read still moves past its one byte,
		// so a caller walking a run of frames can skip an absent node
		// deliberately rather than being unable to tell one from a malformed
		// frame.
		consumed := 0
		if !exact {
			consumed = 1
		}
		return nil, consumed, newParseError(AbsentNode, "")
	default:
		return nil, 0, newParseError(
			UnsupportedVersion, "version '%d'", version)
	}

	// The domain, terminated by a zero byte and no longer than the published
	// maximum.
	start := at
	limit := total
	if start+maximumDomainLength+1 < limit {
		limit = start + maximumDomainLength + 1
	}
	terminated := false
	for at < limit {
		if b[at] == 0 {
			terminated = true
			break
		}
		at++
	}
	if !terminated {
		// Either the buffer ended inside the domain, or the domain ran past
		// the maximum without terminating. The second is a domain that cannot
		// be valid rather than data that merely stopped, so the two are
		// reported differently.
		if at >= total && at-start <= maximumDomainLength {
			return nil, 0, newParseError(UnexpectedEnd, "domain not complete")
		}
		return nil, 0, newParseError(
			InvalidDomainEncoding,
			"longer than the '%d' character maximum, or not terminated",
			maximumDomainLength)
	}
	domain := string(b[start:at])
	at++

	// The date, whose width depends on the version.
	var date time.Time
	if version == owidVersion1 {
		if total-at < 2 {
			return nil, 0, newParseError(UnexpectedEnd, "date not complete")
		}
		// Version 1 counts days, not hours. The other ports differ here and
		// each one matches its own history; this reader must not quietly
		// change what a version 1 OWID means in Go. Two bytes reach 65,535
		// days, which is June 2199, and a time.Duration holds about 292
		// years, so this arithmetic cannot overflow and needs no guard.
		days := int(b[at])<<8 | int(b[at+1])
		at += 2
		date = ioDateBase.Add(time.Duration(days) * time.Hour * 24)
	} else {
		if total-at < 4 {
			return nil, 0, newParseError(UnexpectedEnd, "date not complete")
		}
		minutes := binary.LittleEndian.Uint32(b[at : at+4])
		at += 4
		// Built through the calendar rather than a time.Duration, which
		// wraps silently past April 2312 while the wire runs to 10186.
		date = dateFromMinutes(minutes)
	}

	if total-at < 4 {
		return nil, 0, newParseError(
			UnexpectedEnd, "payload length not complete")
	}
	declared := binary.LittleEndian.Uint32(b[at : at+4])
	at += 4

	// The declaration is the sender's claim about a payload not yet read, so
	// it is compared with what is actually present before anything is sized by
	// it. Computed signed and wide, so that a buffer with fewer bytes left
	// than a signature needs gives a negative count rather than wrapping, and
	// a negative count can never equal a declaration.
	//
	// The disagreement is the finding even when the buffer also stopped early.
	// What a reader can say for certain is that the declared payload cannot
	// leave exactly the signature the version requires, and that is true
	// whichever way the bytes fall short.
	//
	// The two contracts differ here, and only here. An exact buffer knows the
	// envelope boundary, so the declaration must leave exactly the signature
	// and no more. A framed reader does not: what follows may be the next
	// envelope, so it needs the declaration and the signature to be present
	// and says nothing about the rest.
	present := int64(total-at) - int64(signatureLength)
	if exact {
		if present != int64(declared) {
			return nil, 0, newParseError(
				ByteCountMismatch,
				"declared '%d' with '%d' present", declared, present)
		}
	} else if present < int64(declared) {
		// A frame running past the bytes supplied is data stopping early, not
		// a declaration disagreeing with data that is all present. A caller
		// reading from a source still arriving needs to know whether waiting
		// for more bytes would help, and those are different answers.
		return nil, 0, newParseError(
			UnexpectedEnd,
			"declared '%d' with '%d' present", declared, present)
	}

	// The bytes are all here. Whether this runtime can index them as one slice
	// is a separate question, and a different answer, because the same
	// envelope may be readable elsewhere.
	if uint64(declared) > uint64(math.MaxInt) {
		return nil, 0, newParseError(
			ImplementationCapacityExceeded, "declared '%d'", declared)
	}

	payload := make([]byte, declared)
	copy(payload, b[at:at+int(declared)])
	at += int(declared)

	signature := make([]byte, signatureLength)
	copy(signature, b[at:at+signatureLength])
	at += signatureLength

	if exact && at != total {
		// Unreachable while the count check above holds, and kept so that a
		// future change to that arithmetic cannot silently start accepting
		// trailing bytes.
		return nil, 0, newParseError(MalformedEnvelope, "bytes after the envelope")
	}

	return &OWID{
		version:   version,
		domain:    domain,
		date:      date,
		payload:   payload,
		signature: signature,
	}, at, nil
}
