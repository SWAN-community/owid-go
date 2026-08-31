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
	"math"
	"testing"
	"time"
)

// Dates the wire format can carry but a time.Duration cannot.
//
// Versions 2 and 3 carry the date as an unsigned 32 bit count of minutes
// since 2020-01-01, which runs to 4,294,967,295 and lands on 15 February
// 10186. A time.Time holds that, so unlike .NET and Python, which stop at the
// year 9999 and refuse with ImplementationCapacityExceeded, Go computes the
// date. Before the fix the count was converted to a time.Duration, which is
// int64 nanoseconds and runs out at 153,722,867 minutes, so any count from
// 153,722,868 upwards wrapped silently and the parse succeeded with a wrong
// date. Both reading contracts are checked, and a round trip, because the
// writer had the same limit and a verifier rebuilds the signed bytes from
// the parsed fields.

const (
	// lastDurationMinutes is the last count a time.Duration can hold,
	// which is 2312-04-11 23:47. Written as a number here and checked
	// against the runtime below.
	lastDurationMinutes = 153722867

	// firstWrappingMinutes is the first count that overflowed a Duration.
	firstWrappingMinutes = lastDurationMinutes + 1
)

// withMinutes returns a signed version 3 envelope with its date bytes
// replaced. The date follows the version byte and the terminated domain, as
// four little endian bytes. The signature no longer matches, which does not
// matter, because parsing and verifying are separate questions.
func withMinutes(t *testing.T, minutes uint32) []byte {
	t.Helper()
	o, err := contractCreator(t).Create([]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	b, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	at := 1 + len(testDomain) + 1
	binary.LittleEndian.PutUint32(b[at:at+4], minutes)
	return b
}

// version1WithDays returns a version 1 envelope built by hand, because no
// creator writes that version any more. Two big endian bytes of days, then
// the payload count, payload and a signature of the right length.
func version1WithDays(days uint16) []byte {
	var b bytes.Buffer
	b.WriteByte(owidVersion1)
	b.WriteString(testDomain)
	b.WriteByte(0)
	b.WriteByte(byte(days >> 8))
	b.WriteByte(byte(days))
	b.Write([]byte{1, 0, 0, 0, 7})
	b.Write(make([]byte, signatureLength))
	return b.Bytes()
}

// dateOnBothContracts reads the envelope whole and framed, requires both to
// succeed and agree, and returns the date they read.
func dateOnBothContracts(t *testing.T, b []byte) time.Time {
	t.Helper()
	whole, err := FromByteArray(b)
	if err != nil {
		t.Fatalf("whole buffer read failed: %v", err)
	}
	framed, err := FromBuffer(bytes.NewBuffer(b))
	if err != nil {
		t.Fatalf("framed read failed: %v", err)
	}
	if !whole.Date().Equal(framed.Date()) {
		t.Errorf("reads disagree: %v and %v", whole.Date(), framed.Date())
	}
	return whole.Date()
}

func assertDate(t *testing.T, minutes uint32, want time.Time) {
	t.Helper()
	b := withMinutes(t, minutes)
	got := dateOnBothContracts(t, b)
	if !got.Equal(want) {
		t.Errorf("count %d read as %v, want %v", minutes, got, want)
	}
	// The parsed fields write back as the bytes that were read, so a far
	// date survives a round trip and the bytes a verifier rebuilds are the
	// ones that were signed.
	o, err := FromByteArray(b)
	if err != nil {
		t.Fatal(err)
	}
	again, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, again) {
		t.Errorf("count %d did not survive a round trip", minutes)
	}
}

// TestMaximumCountReadsAsTheRightDate covers the largest count the wire can
// carry, which a time.Time holds and a time.Duration does not.
func TestMaximumCountReadsAsTheRightDate(t *testing.T) {
	assertDate(t, math.MaxUint32,
		time.Date(10186, 2, 15, 4, 15, 0, 0, time.UTC))
}

// TestFirstCountPastADurationReadsAsTheRightDate covers the first count that
// wrapped before the fix.
func TestFirstCountPastADurationReadsAsTheRightDate(t *testing.T) {
	assertDate(t, firstWrappingMinutes,
		time.Date(2312, 4, 11, 23, 48, 0, 0, time.UTC))
}

// TestLastCountInsideADurationReadsAsTheRightDate covers the last count that
// was already right, so the fix is shown to change nothing below the
// boundary.
func TestLastCountInsideADurationReadsAsTheRightDate(t *testing.T) {
	assertDate(t, lastDurationMinutes,
		time.Date(2312, 4, 11, 23, 47, 0, 0, time.UTC))
}

// TestTheBoundaryIsWhereADurationOverflows pins the counts above to the
// runtime rather than to a calculation someone did once.
func TestTheBoundaryIsWhereADurationOverflows(t *testing.T) {
	if math.MaxInt64/int64(time.Minute) != lastDurationMinutes {
		t.Errorf("a Duration holds %d whole minutes, the test assumes %d",
			math.MaxInt64/int64(time.Minute), lastDurationMinutes)
	}
	// Through variables, because the compiler refuses the overflow when it
	// can see the whole expression, which is a check the reader never had
	// at run time.
	var last, first int64 = lastDurationMinutes, firstWrappingMinutes
	if time.Duration(last)*time.Minute < 0 {
		t.Error("the last count inside should not overflow")
	}
	if time.Duration(first)*time.Minute > 0 {
		t.Error("the first count past should overflow")
	}
}

// TestVersion1MaximumDaysReadsAsTheRightDate shows the two byte field needs
// no guard. Version 1 in Go counts days, so its largest count is 65,535
// days, which is 6 June 2199, and a time.Duration holds about 292 years.
func TestVersion1MaximumDaysReadsAsTheRightDate(t *testing.T) {
	got := dateOnBothContracts(t, version1WithDays(math.MaxUint16))
	want := time.Date(2199, 6, 6, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("read as %v, want %v", got, want)
	}
}
