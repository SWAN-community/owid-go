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
	"strings"
	"testing"
	"time"
)

// crafted builds an OWID with the version, domain and date given and a
// signature of zeroes, for the cases that are about the URL rather than the
// signature. Reading it back is the only way an OWID reaches a caller, so
// the bytes are written and then parsed.
func crafted(t *testing.T, version byte, domain string, date time.Time) *OWID {
	t.Helper()
	var b bytes.Buffer
	if err := writeByte(&b, version); err != nil {
		t.Fatal(err)
	}
	if err := writeString(&b, domain); err != nil {
		t.Fatal(err)
	}
	if err := writeDate(&b, date, version); err != nil {
		t.Fatal(err)
	}
	if err := writeByteArray(&b, []byte{}); err != nil {
		t.Fatal(err)
	}
	if err := writeSignature(&b, make([]byte, signatureLength)); err != nil {
		t.Fatal(err)
	}
	o, err := FromByteArray(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestURLNamesTheVersionTheIdentifierCarries checks that the version segment
// is the OWID's own version byte, so a version 2 identifier asks the version
// 2 end point. Nothing else in this package carries a version other than 3,
// so this is the test that catches a constant put back into the path.
func TestURLNamesTheVersionTheIdentifierCarries(t *testing.T) {
	o := crafted(t, owidVersion2, "example.com",
		ioDateBase.Add(time.Duration(fixtureIdentifierMinutes)*time.Minute))
	if o.Version() != owidVersion2 {
		t.Fatalf("the crafted identifier should be version 2, got %d", o.Version())
	}
	got := o.publicKeyURL("https")
	want := "https://example.com/owid/api/v2/public-key?date=3510720&format=pkcs"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestKeysAreHeldPerRequestAndNotPerDomain checks that keys are held against
// the URL they came from, which names the minute, so two identifiers from
// different weeks fetch two different keys and a key held for one week never
// answers for another. A store keyed by domain alone would hand the second
// identifier the first one's key.
func TestKeysAreHeldPerRequestAndNotPerDomain(t *testing.T) {
	k := newKeyServer(t)
	useServer(t, k.server.URL)
	earlier := crafted(t, owidVersion3, "51d.es",
		ioDateBase.Add(time.Duration(fixtureIdentifierMinutes-14*24*60)*time.Minute))
	later := crafted(t, owidVersion3, "51d.es",
		ioDateBase.Add(time.Duration(fixtureIdentifierMinutes)*time.Minute))
	first, err := earlier.fetchPublicKey("https")
	if err != nil {
		t.Fatal(err)
	}
	second, err := later.fetchPublicKey("https")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two weeks should fetch two different keys")
	}
	if len(k.dates) != 2 {
		t.Fatalf("expected one request per week, got %d", len(k.dates))
	}
	again, err := earlier.fetchPublicKey("https")
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Fatal("the held key should be the one fetched for that week")
	}
	if len(k.dates) != 2 {
		t.Fatalf("a week already held should not be asked for again, got %d requests", len(k.dates))
	}
	if !strings.Contains(first, "BEGIN PUBLIC KEY") {
		t.Fatal("the held value should be the PEM the end point served")
	}
}
