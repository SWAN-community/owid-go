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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Verification against a real creator that rotates its key every week.
//
// The fixtures in testdata are a genuine 51Did creator context identifier
// created on 2026-09-04 for the creator domain 51d.es, and the published
// 51d.es public key schedule of thirty weekly keys from 11 May to 30 November
// 2026. Both are public and carry no secret.
//
// Two things are proved here that nothing proved before. The first is that
// this package verifies a genuine identifier signed by another implementation
// against the schedule that creator actually publishes, rather than only
// against keys these tests made a moment earlier. The second is that an
// outage and a signature that does not match now reach a caller as different
// statuses instead of as the same false with different message text.

// The minute count the fixture identifier was created at, which is
// 2026-09-04T00:00:00Z counted from 2020-01-01. Written out rather than
// computed, so a change to the counting is caught here instead of being
// carried into the expected request as well.
const fixtureIdentifierMinutes = 3510720

// requestMoment is the moment the stand in end point treats as now, a week
// after the fixture identifier was signed. A real creator answers an undated
// request with the key in force at the moment of the request, and clamps a
// date in the future to that moment, so fixing the moment here keeps the
// tests repeatable whilst answering the way the live end point does.
var requestMoment = time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)

// scheduledKey is one entry of the published schedule, being the date the key
// came into force and the PEM the end point serves it as.
type scheduledKey struct {
	startsAt time.Time
	pem      string
}

// fixtureRecords reads a testdata file, dropping the comment lines that
// describe it and any blank lines, and returning the records that remain.
func fixtureRecords(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			r = append(r, l)
		}
	}
	return r
}

// fixtureIdentifier is the genuine identifier from testdata.
func fixtureIdentifier(t *testing.T) *OWID {
	t.Helper()
	r := fixtureRecords(t, "identifier.txt")
	if len(r) != 1 {
		t.Fatalf("the fixture should hold one identifier, got %d", len(r))
	}
	o, err := FromBase64(r[0])
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// fixtureSchedule is the published schedule from testdata, oldest key first.
// The fixture stores the base 64 body of each key, which is wrapped back into
// the PEM the end point serves.
func fixtureSchedule(t *testing.T) []scheduledKey {
	t.Helper()
	var s []scheduledKey
	for _, r := range fixtureRecords(t, "public-key-schedule.txt") {
		d, body, found := strings.Cut(r, " ")
		if !found {
			t.Fatalf("a record should be a date and a key, got %q", r)
		}
		at, err := time.Parse(time.RFC3339, d)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for len(body) > 64 {
			lines = append(lines, body[:64])
			body = body[64:]
		}
		lines = append(lines, body)
		s = append(s, scheduledKey{
			startsAt: at,
			pem: "-----BEGIN PUBLIC KEY-----\n" +
				strings.Join(lines, "\n") +
				"\n-----END PUBLIC KEY-----\n"})
	}
	return s
}

// keyInForce returns the key that was in force at the date given, which is the
// newest one that had already started, or nil where the schedule starts after
// the date.
func keyInForce(s []scheduledKey, d time.Time) *scheduledKey {
	for i := len(s) - 1; i >= 0; i-- {
		if !s[i].startsAt.After(d) {
			return &s[i]
		}
	}
	return nil
}

// keyServer stands in for the creator's public key end point, answering the
// way the cloud controller does. A request naming a date is served the key
// that was in force then, a request without one is served the key in force
// at requestMoment, a date after requestMoment is read as requestMoment, and
// a date the schedule does not reach is a 404.
//
// It records the date parameter of every request, so a test can say what went
// over the wire rather than only what the client meant to send.
type keyServer struct {
	server   *httptest.Server
	schedule []scheduledKey
	dates    []string
}

func newKeyServer(t *testing.T) *keyServer {
	t.Helper()
	k := &keyServer{schedule: fixtureSchedule(t)}
	k.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			d := r.URL.Query().Get("date")
			k.dates = append(k.dates, d)
			asked := requestMoment
			if d != "" {
				m, err := strconv.ParseInt(d, 10, 64)
				if err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				asked = ioDateBase.Add(time.Duration(m) * time.Minute)
				if asked.After(requestMoment) {
					asked = requestMoment
				}
			}
			key := keyInForce(k.schedule, asked)
			if key == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprint(w, key.pem)
		}))
	t.Cleanup(k.server.Close)
	return k
}

// useServer points the package HTTP client at the URL given for the duration
// of the test, leaving the OWID's real domain intact because the signature
// covers the domain.
func useServer(t *testing.T, raw string) {
	t.Helper()
	// Keys are held against the URL they were fetched from, and every test
	// here asks for the same identifier's key, so each starts with nothing
	// held.
	ClearKeyCache()
	t.Cleanup(ClearKeyCache)
	target, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	orig := client
	t.Cleanup(func() { client = orig })
	// Built the way production builds it, so the redirect policy is under
	// test here and not only in init.
	client = newKeyClient(&redirectTransport{target: target})
}

// TestFixtureIdentifierVerifiesAgainstThePublishedSchedule checks a genuine
// identifier against the key the published 51d.es schedule says was in force
// on the day it was created, with no HTTP involved. This is the fixed point
// the tests that do use HTTP are measured against.
func TestFixtureIdentifierVerifiesAgainstThePublishedSchedule(t *testing.T) {
	o := fixtureIdentifier(t)
	if o.Domain() != "51d.es" {
		t.Fatalf("expected the 51d.es creator, got %q", o.Domain())
	}
	k := keyInForce(fixtureSchedule(t), o.Date())
	if k == nil {
		t.Fatal("the schedule should cover the date the identifier was created")
	}
	if got := k.startsAt.Format(time.RFC3339); got != "2026-08-31T00:00:00Z" {
		t.Errorf("expected the week beginning 31 August, got %s", got)
	}
	if s := o.SignatureStatusWithPublicKey(k.pem); s != SignatureValid {
		t.Errorf("expected SignatureValid, got %s", s)
	}
}

// TestALaterWeeksKeyDoesNotVerifyAnEarlierWeeksIdentifier is why the date has
// to be sent at all. Keys rotate weekly, so the key in force when an
// identifier is checked is not the key that signed it unless the check
// happens in the same week.
func TestALaterWeeksKeyDoesNotVerifyAnEarlierWeeksIdentifier(t *testing.T) {
	o := fixtureIdentifier(t)
	later := keyInForce(fixtureSchedule(t), requestMoment)
	if later == nil {
		t.Fatal("the schedule should cover the moment of the request")
	}
	if !later.startsAt.After(o.Date()) {
		t.Fatalf("the key in force a week later should start after the identifier, got %s", later.startsAt)
	}
	if got := o.SignatureStatusWithPublicKey(later.pem); got != SignatureInvalid {
		t.Errorf("expected SignatureInvalid, got %s", got)
	}
}

// TestFetchAsksForTheKeyInForceWhenTheIdentifierWasSigned drives the fetch
// against a stand in for the 51d.es end point holding the whole published
// schedule, with the identifier signed in a week earlier than the one the end
// point counts as current.
func TestFetchAsksForTheKeyInForceWhenTheIdentifierWasSigned(t *testing.T) {
	o := fixtureIdentifier(t)
	k := newKeyServer(t)
	useServer(t, k.server.URL)

	if s := o.SignatureStatusFromDomain("https"); s != SignatureValid {
		t.Errorf("expected SignatureValid, got %s", s)
	}
	want := strconv.Itoa(fixtureIdentifierMinutes)
	if len(k.dates) != 1 || k.dates[0] != want {
		t.Errorf("expected one request naming date %s, got %v", want, k.dates)
	}
}

// TestVerifyAndStatusAgreeOnTheFetchedKey checks that the boolean form and the
// status form of the same fetch reach the same answer, since they now share
// one route to the key.
func TestVerifyAndStatusAgreeOnTheFetchedKey(t *testing.T) {
	o := fixtureIdentifier(t)
	k := newKeyServer(t)
	useServer(t, k.server.URL)

	valid, err := o.Verify("https")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("the genuine identifier should verify")
	}
	if s := o.SignatureStatusFromDomain("https"); s != SignatureValid {
		t.Errorf("expected SignatureValid, got %s", s)
	}
}

// TestOutageIsKeyUnavailableAndNotAForgery is the defect this file was added
// for. The 401 that 51d.es returns without a resource key, and a signature
// that genuinely does not match, both came back from Verify as false with an
// error, so they were told apart only by reading the message text. They are
// now different statuses.
func TestOutageIsKeyUnavailableAndNotAForgery(t *testing.T) {
	o := fixtureIdentifier(t)
	for _, code := range []int{
		http.StatusUnauthorized,
		http.StatusNotFound,
		http.StatusInternalServerError} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(code)
				}))
			defer s.Close()
			useServer(t, s.URL)

			if got := o.SignatureStatusFromDomain("https"); got != KeyUnavailable {
				t.Errorf("expected KeyUnavailable, got %s", got)
			}

			// The boolean form keeps the message it always had, so
			// callers reading it are not broken by the status being
			// added alongside.
			valid, err := o.Verify("https")
			if valid {
				t.Error("nothing should verify when no key arrived")
			}
			want := fmt.Sprintf("Domain '51d.es' return code '%d'", code)
			if err == nil || err.Error() != want {
				t.Errorf("expected %q, got %v", want, err)
			}
			var k *KeyFetchError
			if !errors.As(err, &k) {
				t.Fatalf("expected a KeyFetchError, got %v", err)
			}
			if k.Status != KeyUnavailable || k.StatusCode != code {
				t.Errorf(
					"expected KeyUnavailable and %d, got %s and %d",
					code, k.Status, k.StatusCode)
			}
		})
	}
}

// TestFetchedKeyThatDidNotSignIsSignatureInvalid is the other half of the
// pair. A key that arrives intact and does not match the signature is the one
// answer that means the identifier should be distrusted.
func TestFetchedKeyThatDidNotSignIsSignatureInvalid(t *testing.T) {
	o := fixtureIdentifier(t)
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	other, err := c.publicKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, other)
		}))
	defer s.Close()
	useServer(t, s.URL)

	if got := o.SignatureStatusFromDomain("https"); got != SignatureInvalid {
		t.Errorf("expected SignatureInvalid, got %s", got)
	}
}

// TestFetchedKeyThatCannotBeReadIsInvalidKey covers the 30 August 2026 case
// where the end points served PEM a strict parser rejects. The fault is in
// the key and the signature was never examined, so this must not read as an
// attack either.
func TestFetchedKeyThatCannotBeReadIsInvalidKey(t *testing.T) {
	o := fixtureIdentifier(t)
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "-----BEGIN PUBLIC KEY-----\nnot a key\n")
		}))
	defer s.Close()
	useServer(t, s.URL)

	if got := o.SignatureStatusFromDomain("https"); got != InvalidKey {
		t.Errorf("expected InvalidKey, got %s", got)
	}
}

// TestARedirectIsNotFollowed proves a creator whose domain answers with a
// redirect does not get the key at the other end trusted as its own. The
// other end here serves the genuine key that would verify the identifier,
// so following the redirect would read as SignatureValid, and refusing it
// must read as the key being unavailable with the 302 carried. Without
// this a network attacker able to bend a creator's DNS, or a creator that
// was misconfigured, could substitute the key and forgeries would verify.
func TestARedirectIsNotFollowed(t *testing.T) {
	o := fixtureIdentifier(t)
	k := keyInForce(fixtureSchedule(t), o.Date())
	if k == nil {
		t.Fatal("the schedule should cover the date")
	}
	elsewhere := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, k.pem)
		}))
	defer elsewhere.Close()
	followed := false
	creator := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+"/key.pem", http.StatusFound)
		}))
	defer creator.Close()
	elsewhere.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			followed = true
			fmt.Fprint(w, k.pem)
		})
	useServer(t, creator.URL)

	if got := o.SignatureStatusFromDomain("https"); got != KeyUnavailable {
		t.Errorf("expected KeyUnavailable, got %s", got)
	}
	_, err := o.fetchPublicKey("https")
	var kf *KeyFetchError
	if !errors.As(err, &kf) {
		t.Fatalf("expected a KeyFetchError, got %v", err)
	}
	if kf.StatusCode != http.StatusFound {
		t.Errorf("expected the 302 to be carried, got %d", kf.StatusCode)
	}
	if followed {
		t.Error("the request that would have gone to the other host was made")
	}
}

// TestNoResponseAtAllIsKeyUnavailable covers the creator domain not answering,
// where there is no status code to report.
func TestNoResponseAtAllIsKeyUnavailable(t *testing.T) {
	o := fixtureIdentifier(t)
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {}))
	s.Close()
	useServer(t, s.URL)

	if got := o.SignatureStatusFromDomain("https"); got != KeyUnavailable {
		t.Errorf("expected KeyUnavailable, got %s", got)
	}
	_, err := o.Verify("https")
	var k *KeyFetchError
	if !errors.As(err, &k) {
		t.Fatalf("expected a KeyFetchError, got %v", err)
	}
	if k.StatusCode != 0 {
		t.Errorf("expected no status code, got %d", k.StatusCode)
	}
}
