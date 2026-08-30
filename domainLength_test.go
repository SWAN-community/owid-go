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
	"encoding/json"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The creator domain of an OWID ends at a zero terminator that the sender
// supplied, so parsing must stop looking for that terminator at the
// published maximum length of a domain rather than at the end of the
// buffer. These tests prove that a domain of the maximum length still round
// trips, that a longer one is refused, that a buffer with no terminator at
// all is refused with the work bounded by the maximum rather than by the
// size of the buffer, and that the library's own output still parses.

// domainLengthPayload is the payload used by the envelopes below, being 8
// bytes of 0x5A. The tests here are about the domain field, so the payload
// only has to be present and consistent.
var domainLengthPayload = bytes.Repeat([]byte{0x5A}, 8)

// domainLengthSignature is a 64 byte stand in for a signature. The tests
// here are about the shape of the envelope, not the cryptography, so the
// bytes do not need to verify.
var domainLengthSignature = bytes.Repeat([]byte{0x99}, signatureLength)

// domainLengthEnvelope builds a version 3 envelope carrying the domain
// given, being the version byte, the domain with its zero terminator, four
// minute bytes, the payload length, the payload and the signature.
func domainLengthEnvelope(domain string) []byte {
	var b bytes.Buffer
	b.WriteByte(owidVersion3)
	b.WriteString(domain)
	b.WriteByte(0)
	minutes := make([]byte, 4)
	binary.LittleEndian.PutUint32(minutes, 1000)
	b.Write(minutes)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(len(domainLengthPayload)))
	b.Write(length)
	b.Write(domainLengthPayload)
	b.Write(domainLengthSignature)
	return b.Bytes()
}

// domainLengthName returns a domain of exactly the number of characters
// given, built from labels of at most the 63 characters RFC 1035 allows,
// separated by dots.
func domainLengthName(n int) string {
	var b strings.Builder
	for b.Len() < n {
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		for i := 0; i < 63 && b.Len() < n; i++ {
			b.WriteByte('a')
		}
	}
	return b.String()
}

// TestDomainLengthMaximumParses proves that a domain of exactly the
// published maximum length parses and that its value round trips
// unchanged, so the bound refuses nothing that is valid.
func TestDomainLengthMaximumParses(t *testing.T) {
	d := domainLengthName(maximumDomainLength)
	if len(d) != maximumDomainLength {
		t.Fatalf(
			"expected a '%d' character domain, built '%d'",
			maximumDomainLength,
			len(d))
	}
	o, err := FromByteArray(domainLengthEnvelope(d))
	if err != nil {
		t.Fatalf("a domain of the maximum length should parse: %v", err)
	}
	if o.domain != d {
		t.Errorf("expected domain '%s', found '%s'", d, o.domain)
	}
	if bytes.Equal(o.payload, domainLengthPayload) == false {
		t.Error("payload does not match the input")
	}
	if bytes.Equal(o.signature, domainLengthSignature) == false {
		t.Error("signature does not match the input")
	}
}

// TestDomainLengthOverMaximumRefused proves that a domain one character
// longer than the published maximum is refused, even though it carries a
// terminator and the rest of the envelope is well formed.
func TestDomainLengthOverMaximumRefused(t *testing.T) {
	d := domainLengthName(maximumDomainLength + 1)
	if len(d) != maximumDomainLength+1 {
		t.Fatalf(
			"expected a '%d' character domain, built '%d'",
			maximumDomainLength+1,
			len(d))
	}
	_, err := FromByteArray(domainLengthEnvelope(d))
	if err == nil {
		t.Errorf(
			"a domain of '%d' characters should be refused",
			len(d))
	}
}

// TestDomainLengthNoTerminatorRefusedWithoutReading proves that a buffer
// whose domain field has no terminator at all is refused with the work
// bounded by the maximum domain length rather than by the size of the
// buffer. The buffer holds 16 MiB of domain characters after the version
// byte. Two bounds are asserted, being that none of those bytes are
// consumed, which the unread count after the refusal shows, and that the
// refusal allocates under 64 KiB, measured as the change in total bytes
// reported by the runtime.
func TestDomainLengthNoTerminatorRefusedWithoutReading(t *testing.T) {
	d := bytes.Repeat([]byte{'a'}, 16*1024*1024)
	var e bytes.Buffer
	e.WriteByte(owidVersion3)
	e.Write(d)
	b := bytes.NewBuffer(e.Bytes())
	consumed := b.Len()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := FromBuffer(b)
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("a domain with no terminator should be refused")
	}
	remaining := b.Len()
	if remaining != consumed-1 {
		t.Errorf(
			"expected '%d' bytes left unread after the version byte, "+
				"found '%d'",
			consumed-1,
			remaining)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= 64*1024 {
		t.Errorf(
			"refusing a domain with no terminator allocated '%d' bytes",
			allocated)
	}
}

// TestDomainLengthLibraryOutputParses proves that an OWID created and
// signed by the library's own signing path still parses, so the bound
// agrees with what the library itself produces.
func TestDomainLengthLibraryOutputParses(t *testing.T) {
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
	if n.domain != o.domain {
		t.Errorf("expected domain '%s', found '%s'", o.domain, n.domain)
	}
	if o.compare(n) == false {
		t.Error("library output did not round trip")
	}
}

// The write half of the same bound. A domain longer than the published
// maximum is refused where a domain enters the library, being the OWID
// factory, the creator factory that the registration end point and every
// store build creators through, the JSON route a creator takes out of a
// local store, and the registration end point itself, which takes the
// domain from the Host header of the request. Serialisation refuses one as
// well, so a domain that arrives by another route, such as an assignment to
// the exported Domain field, cannot reach the wire in a form this same
// library would refuse to read back.

// requireDomainLengthError checks that the error is present and that it
// names the maximum, since a caller told only that the domain is wrong
// cannot tell how much shorter it has to be.
func requireDomainLengthError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a domain over the maximum should be refused")
	}
	if strings.Contains(
		err.Error(),
		strconv.Itoa(maximumDomainLength)) == false {
		t.Errorf(
			"expected the '%d' character maximum to be named, found '%s'",
			maximumDomainLength,
			err.Error())
	}
}

// TestDomainLengthWriteMaximumRoundTrips proves that a creator whose domain
// is exactly the published maximum still creates, signs and serialises an
// OWID, that the result parses back to the same domain and that the
// signature over that domain still verifies.
func TestDomainLengthWriteMaximumRoundTrips(t *testing.T) {
	d := domainLengthName(maximumDomainLength)
	c, err := newTestCreator(d, testOrgName, registerContractURL)
	if err != nil {
		t.Fatalf("a domain of the maximum length should be accepted: %v", err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
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
	if n.domain != d {
		t.Errorf("expected domain '%s', found '%s'", d, n.domain)
	}
	v, err := c.Verify(n)
	if err != nil {
		t.Fatal(err)
	}
	if v == false {
		t.Error("the round tripped OWID did not verify")
	}
}

// TestDomainLengthEmptyDomainUnchanged proves that an empty domain behaves
// as it did before the bound, being written as a bare terminator and read
// back as an empty string.
func TestDomainLengthEmptyDomainUnchanged(t *testing.T) {
	o, err := newOwid("", testDate, []byte(testPayload))
	if err != nil {
		t.Fatalf("an empty domain should be accepted: %v", err)
	}
	o.signature = domainLengthSignature
	a, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	n, err := FromByteArray(a)
	if err != nil {
		t.Fatal(err)
	}
	if n.domain != "" {
		t.Errorf("expected an empty domain, found '%s'", n.domain)
	}
}

// TestDomainLengthNewOwidOverMaximumRefused proves that the OWID factory
// refuses a domain one character over the maximum.
func TestDomainLengthNewOwidOverMaximumRefused(t *testing.T) {
	_, err := newOwid(
		domainLengthName(maximumDomainLength+1),
		testDate,
		[]byte(testPayload))
	requireDomainLengthError(t, err)
}

// TestDomainLengthCreatorOverMaximumRefused proves that the creator factory
// refuses a domain one character over the maximum, so a creator that would
// sign unreadable OWIDs is never built.
func TestDomainLengthCreatorOverMaximumRefused(t *testing.T) {
	_, err := newTestCreator(
		domainLengthName(maximumDomainLength+1),
		testOrgName,
		registerContractURL)
	requireDomainLengthError(t, err)
}

// TestDomainLengthCreatorJSONOverMaximumRefused proves that a creator read
// back from a store as JSON, which does not pass through the creator
// factory, is refused the same way.
func TestDomainLengthCreatorJSONOverMaximumRefused(t *testing.T) {
	j, err := json.Marshal(map[string]string{
		"domain": domainLengthName(maximumDomainLength + 1)})
	if err != nil {
		t.Fatal(err)
	}
	var c Creator
	requireDomainLengthError(t, c.UnmarshalJSON(j))
}

// TestDomainLengthSerialisationOverMaximumRefused proves that a domain
// assigned straight to the exported field, which passes no factory at all,
// is still refused when the OWID is serialised.
func TestDomainLengthSerialisationOverMaximumRefused(t *testing.T) {
	var o OWID
	o.version = owidVersion3
	o.domain = domainLengthName(maximumDomainLength + 1)
	o.date = testDate
	o.payload = domainLengthPayload
	o.signature = domainLengthSignature
	_, err := o.AsByteArray()
	requireDomainLengthError(t, err)
}

// TestDomainLengthRegisterOverMaximumRefused proves that the registration
// end point refuses a Host header longer than the maximum, so the person
// registering is told at that point, and that nothing is stored for it.
func TestDomainLengthRegisterOverMaximumRefused(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	d := domainLengthName(maximumDomainLength + 1)
	rr := sendRaw(
		t,
		HandlerRegister(s),
		d,
		"/owid/api/v1/register",
		url.Values{})
	if rr == nil {
		t.Fatal("no response from the register handler")
	}
	if rr.Code != http.StatusInternalServerError {
		t.Errorf(
			"expected status '%d', found '%d'",
			http.StatusInternalServerError,
			rr.Code)
	}
	if strings.Contains(
		rr.Body.String(),
		strconv.Itoa(maximumDomainLength)) == false {
		t.Errorf(
			"expected the maximum named in the response, found '%s'",
			rr.Body.String())
	}
	c, err := s.store.GetCreator(d)
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Error("a domain over the maximum should not be registered")
	}
}

// TestDomainLengthRefusedBeforeSigning proves that a domain over the
// maximum is refused before any signature is computed, since signing a
// value that will be refused is wasted work. The creator holds a private
// key that cannot be parsed, so had the refusal come after the signing step
// the error would name the key rather than the maximum. The creator is
// built directly because the creator factory now refuses the domain.
func TestDomainLengthRefusedBeforeSigning(t *testing.T) {
	c := Creator{
		domain:     domainLengthName(maximumDomainLength + 1),
		privateKey: "not a private key"}
	_, err := c.CreateOWIDandSign([]byte(testPayload))
	requireDomainLengthError(t, err)
}

// TestDomainLengthSigningReachedAtMaximum proves that the ordering test
// above fails for the reason it claims. The same unparsable private key
// with a domain of exactly the maximum passes the domain check, reaches the
// signing step and reports the key, which shows that the signing step is
// live and would have reported the key first had the domain check not run
// before it.
func TestDomainLengthSigningReachedAtMaximum(t *testing.T) {
	c := Creator{
		domain:     domainLengthName(maximumDomainLength),
		privateKey: "not a private key"}
	_, err := c.CreateOWIDandSign([]byte(testPayload))
	if err == nil {
		t.Fatal("an unparsable private key should be refused")
	}
	if strings.Contains(err.Error(), strconv.Itoa(maximumDomainLength)) {
		t.Errorf(
			"expected the key to be reported, found '%s'",
			err.Error())
	}
}
