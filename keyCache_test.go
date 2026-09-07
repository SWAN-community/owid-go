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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The key cache holds each key against the span of minutes it is known to
// cover, rather than against the minute of one identifier. The tests here
// drive fetchPublicKey against a stand in end point that answers the way the
// handler in this package answers, with identifiers dated in the past so the
// cache reads each minute as itself rather than as now.

// at is a moment given as RFC 3339 text.
func at(t *testing.T, moment string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, moment)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// pemAt is the PEM the fetch answers for an identifier from 51d.es dated at
// the moment.
func pemAt(t *testing.T, moment time.Time) string {
	t.Helper()
	pem, err := crafted(t, owidVersion3, "51d.es", moment).fetchPublicKey("https")
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// inForceAt is the PEM the published schedule says was in force at the
// moment.
func inForceAt(t *testing.T, k *keyServer, moment time.Time) string {
	t.Helper()
	key := keyInForce(k.schedule, moment)
	if key == nil {
		t.Fatalf("the schedule should reach %v", moment)
	}
	return key.pem
}

// TestAMinuteBetweenTwoConfirmedMinutesIsServedFromTheCache checks that a key
// the creator has confirmed for two minutes is served for every minute
// between them without a request, because a key is in force from the start
// of its period until the next key starts, and that a minute outside every
// confirmed span is asked about.
func TestAMinuteBetweenTwoConfirmedMinutesIsServedFromTheCache(t *testing.T) {
	k := newSpanlessKeyServer(t)
	useServer(t, k.server.URL)
	// The week of 31 August 2026, which the fixture identifier was signed
	// in, and which is wholly in the past.
	first := at(t, "2026-08-31T00:01:00Z")
	last := at(t, "2026-09-06T23:00:00Z")
	pem := pemAt(t, first)
	if pemAt(t, last) != pem {
		t.Fatal("one key should cover the week")
	}
	if len(k.dates) != 2 {
		t.Fatalf("the two ends of the span should be asked about, got %d requests", len(k.dates))
	}
	for _, between := range []time.Time{
		first.Add(time.Minute), first.Add(3 * 24 * time.Hour), last.Add(-time.Minute)} {
		if pemAt(t, between) != pem {
			t.Fatalf("the key served for %v should be the week's key", between)
		}
	}
	if len(k.dates) != 2 {
		t.Fatalf("a minute between two confirmed minutes should not be asked about, got %d requests", len(k.dates))
	}
	if cachedKeyCount() != 1 {
		t.Fatalf("one key should be held however many minutes it covers, got %d", cachedKeyCount())
	}
	if pemAt(t, first.Add(-2*time.Minute)) == pem {
		t.Fatal("a minute in the week before should be the earlier week's key")
	}
	if len(k.dates) != 3 {
		t.Fatalf("a minute before the span should be asked about, got %d requests", len(k.dates))
	}
	if cachedKeyCount() != 2 {
		t.Fatalf("the earlier week's key should be held as a second key, got %d", cachedKeyCount())
	}
}

// TestAHundredIdentifiersInOneConfirmedPeriodMakeNoRequest is the case that
// made the cache almost useless when it was keyed by the whole URL. A hundred
// identifiers with a hundred different minutes inside one key's period cost a
// hundred requests then. With the ends of the period confirmed they cost none.
func TestAHundredIdentifiersInOneConfirmedPeriodMakeNoRequest(t *testing.T) {
	k := newSpanlessKeyServer(t)
	useServer(t, k.server.URL)
	start := at(t, "2026-09-01T00:00:00Z")
	pemAt(t, start)
	pemAt(t, start.Add(100*time.Minute))
	for i := 1; i <= 100; i++ {
		pemAt(t, start.Add(time.Duration(i)*time.Minute))
	}
	if len(k.dates) != 2 {
		t.Fatalf("a hundred identifiers over a hundred minutes should make no request once both ends of the span are known, got %d", len(k.dates))
	}
}

// TestAKeyIsNeverServedForAMinuteOutsideItsConfirmedSpan checks that a key is
// only ever served for a minute inside the span the creator has confirmed it
// for. Where the creator rotated between two confirmed minutes, the minutes
// between them belong to neither key until the creator is asked, and every
// answer agrees with the published schedule.
func TestAKeyIsNeverServedForAMinuteOutsideItsConfirmedSpan(t *testing.T) {
	k := newSpanlessKeyServer(t)
	useServer(t, k.server.URL)
	rotation := at(t, "2026-08-31T00:00:00Z")
	week := 7 * 24 * time.Hour
	// The start of the week before the rotation and the end of the week
	// after it, so the two keys are held with the rotation between.
	pemAt(t, rotation.Add(-week))
	pemAt(t, rotation.Add(week-time.Minute))
	if len(k.dates) != 2 || cachedKeyCount() != 2 {
		t.Fatalf("two keys should be held after two requests, got %d requests and %d keys", len(k.dates), cachedKeyCount())
	}

	// Every minute across the rotation, in an order that walks in from both
	// sides, is answered with the key the schedule gives, whether from the
	// cache or by asking.
	moments := []time.Time{
		rotation.Add(-time.Minute), rotation, rotation.Add(-2 * time.Minute), rotation.Add(time.Minute),
		rotation.Add(-week / 2), rotation.Add(week / 2),
		rotation.Add(-3 * time.Minute), rotation.Add(2 * time.Minute), rotation.Add(-time.Minute), rotation,
	}
	for _, moment := range moments {
		if pemAt(t, moment) != inForceAt(t, k, moment) {
			t.Fatalf("the key served for %v should be the schedule's", moment)
		}
	}
	if cachedKeyCount() != 2 {
		t.Fatalf("two keys should be held, each with its own span, got %d", cachedKeyCount())
	}
	asked := len(k.dates)
	if asked <= 2 || asked >= 2+len(moments) {
		t.Fatalf("some minutes should be asked about and some served, got %d requests", asked)
	}

	// The minute either side of the rotation is now confirmed, so nothing
	// across the whole fortnight needs asking.
	for moment := rotation.Add(-week); moment.Before(rotation.Add(week)); moment = moment.Add(time.Hour) {
		if pemAt(t, moment) != inForceAt(t, k, moment) {
			t.Fatalf("the key served for %v should be the schedule's", moment)
		}
	}
	if len(k.dates) != asked {
		t.Fatalf("both spans are fully confirmed so nothing should be asked, got %d more requests", len(k.dates)-asked)
	}
}

// TestAMinuteWithinTheDriftAllowanceIsNotHeld checks that a minute within the
// clock drift allowance of now, or later, is asked about every time and never
// held, because a creator whose clock differs from this one's may have read it
// as its present rather than as the minute named, and that a minute beyond
// the allowance is held as usual. Live identifiers from a creator that states
// no span therefore cost one request per minute and older ones cost none.
func TestAMinuteWithinTheDriftAllowanceIsNotHeld(t *testing.T) {
	k := newSpanlessKeyServer(t)
	useServer(t, k.server.URL)
	started := minutesSinceBase(time.Now().UTC())
	now := time.Now().UTC()
	recent := now.Add(-time.Minute)
	pemAt(t, recent)
	pemAt(t, recent)
	pemAt(t, now.Add(7*24*time.Hour))
	old := now.Add(-time.Duration(clockDriftAllowanceMinutes+1) * time.Minute)
	pemAt(t, old)
	pemAt(t, old)
	if minutesSinceBase(time.Now().UTC()) != started {
		t.Skip("the minute changed during the test, so the calls were not all about the same now")
	}
	if len(k.dates) != 4 {
		t.Fatalf("the recent minute should be asked about twice, the future minute once, and the old minute once with the second call held, got %d requests", len(k.dates))
	}
	if cachedKeyCount() != 1 {
		t.Fatalf("only the old minute's key should be held, got %d", cachedKeyCount())
	}
}

// TestTheKeyCacheIsBounded checks that the cache does not grow without limit.
// The number of distinct keys a verifier is shown is chosen by whoever
// presents the identifiers rather than by this process, so the stand in
// creator here answers every minute with a different key, which is the worst
// a creator can do to the cache.
func TestTheKeyCacheIsBounded(t *testing.T) {
	requests := 0
	// A real key for every minute, because the client checks each answer
	// the way a creator does before sending it.
	distinct := map[string]string{}
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests++
			minute := r.URL.Query().Get("date")
			pem, made := distinct[minute]
			if !made {
				pem = freshPem(t)
				distinct[minute] = pem
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PublicKeyResponse{Format: SpkiFormat, PublicKey: pem})
		}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)
	for i := 0; i <= maximumCachedKeys; i++ {
		pemAt(t, ioDateBase.Add(time.Duration(i)*time.Minute))
	}
	if requests != maximumCachedKeys+1 {
		t.Fatalf("every minute was a different key, so every one should be asked, got %d requests", requests)
	}
	if cachedKeyCount() > maximumCachedKeys {
		t.Fatalf("held %d of at most %d", cachedKeyCount(), maximumCachedKeys)
	}
}

// TestAKeyAnsweredWithItsSpanIsHeldForTheWholeSpan checks that a creator which
// states the moments the key is valid from and to has the whole span held from
// that one answer, so every other minute of the span is served without a
// request.
func TestAKeyAnsweredWithItsSpanIsHeldForTheWholeSpan(t *testing.T) {
	k := newKeyServer(t)
	useServer(t, k.server.URL)
	pem := pemAt(t, at(t, "2026-08-31T00:01:00Z"))
	for _, moment := range []string{"2026-09-06T23:59:00Z", "2026-09-03T12:00:00Z", "2026-08-31T00:00:00Z"} {
		if pemAt(t, at(t, moment)) != pem {
			t.Fatalf("the key served for %s should be the week's key", moment)
		}
	}
	if len(k.dates) != 1 {
		t.Fatalf("the whole week should be held from one answer, got %d requests", len(k.dates))
	}
	if cachedKeyCount() != 1 {
		t.Fatalf("one key should be held, got %d", cachedKeyCount())
	}
	before := pemAt(t, at(t, "2026-08-30T23:59:00Z"))
	if before == pem {
		t.Fatal("the minute before the week should be the earlier week's key")
	}
	pemAt(t, at(t, "2026-08-24T00:00:00Z"))
	if len(k.dates) != 2 {
		t.Fatalf("the earlier week should be held from its one answer, got %d requests", len(k.dates))
	}
}

// TestARecentMinuteIsServedWhereTheCreatorStatedTheSpan checks that the drift
// allowance, which keeps minutes near now out of a cache built from confirmed
// minutes, does not apply to a span the creator stated itself, so live
// identifiers cost one request per key rather than one per minute.
func TestARecentMinuteIsServedWhereTheCreatorStatedTheSpan(t *testing.T) {
	k := newKeyServer(t)
	useServer(t, k.server.URL)
	now := time.Now().UTC()
	current := keyInForce(k.schedule, now)
	if current == nil || nextStart(k.schedule, current) == nil {
		t.Skip("the fixture schedule has no key after the one in force now, so its span has no end")
	}
	pemAt(t, now.Add(-time.Minute))
	pemAt(t, now)
	pemAt(t, now.Add(-10*time.Minute))
	if len(k.dates) != 1 {
		t.Fatalf("the current key should be served for every recent minute from one answer, got %d requests", len(k.dates))
	}
}

// signedAt is an OWID for the domain, dated at the moment, signed with the
// crypto given. It stands for an identifier whose signing machine's clock did
// not agree with the creator's schedule to the minute.
func signedAt(t *testing.T, domain string, moment time.Time, c *Crypto) *OWID {
	t.Helper()
	o, err := newOwid(domain, moment, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.sign(c); err != nil {
		t.Fatal(err)
	}
	return o
}

// TestASignatureFailingNearTheEdgeOfASpanIsCheckedAgainstTheNeighbour checks
// that an identifier dated just after a key started, but signed with the key
// before it, verifies, and one dated just before a key started but signed
// with it verifies too, because the neighbouring key is tried when the
// selected key fails within the drift allowance of the span's edge. Further
// from the edge the failure stands.
func TestASignatureFailingNearTheEdgeOfASpanIsCheckedAgainstTheNeighbour(t *testing.T) {
	first, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	firstPem, err := first.getSubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	secondPem, err := second.getSubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	start := at(t, "2026-08-24T00:00:00Z")
	rotation := at(t, "2026-08-31T00:00:00Z")
	end := at(t, "2026-09-07T00:00:00Z")
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests++
			m, err := strconv.ParseUint(r.URL.Query().Get("date"), 10, 32)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			asked := ioDateBase.Add(time.Duration(m) * time.Minute)
			if asked.Before(rotation) {
				writeKeyAnswer(t, w, true, firstPem, start, &rotation, asked)
				return
			}
			writeKeyAnswer(t, w, true, secondPem, rotation, &end, asked)
		}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)

	// Dated five minutes into the second key's span, signed with the first.
	late := signedAt(t, "creator.test", rotation.Add(5*time.Minute), first)
	if status := late.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("an identifier signed with the earlier key just after the rotation should verify, got %v", status)
	}
	if requests != 2 {
		t.Fatalf("the selected key and then the earlier key should be asked for, got %d requests", requests)
	}
	// Dated five minutes before the rotation, signed with the second key.
	early := signedAt(t, "creator.test", rotation.Add(-5*time.Minute), second)
	if status := early.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("an identifier signed with the later key just before the rotation should verify, got %v", status)
	}
	if requests != 2 {
		t.Fatalf("both keys are held with their spans, so nothing more should be asked, got %d requests", requests)
	}
	// Dated twenty minutes into the second key's span, signed with the
	// first, which is further from the edge than clocks are allowed to
	// differ.
	far := signedAt(t, "creator.test", rotation.Add(20*time.Minute), first)
	if status := far.SignatureStatusFromDomain("https"); status != SignatureInvalid {
		t.Fatalf("an identifier well inside the later key's span signed with the earlier key should not verify, got %v", status)
	}
	if requests != 2 {
		t.Fatalf("the identifier is further from every edge than clocks may differ, so nothing should be asked, got %d requests", requests)
	}
	// The boolean form agrees.
	if valid, err := late.Verify("https"); err != nil || !valid {
		t.Fatalf("Verify should agree with the status, got %v %v", valid, err)
	}
}

// TestTheClientReadsWhatTheHandlerAnswers closes the loop between the two
// halves of this package. The public key handler answers from a schedule, and
// the client verifies identifiers against what it answered, holding the whole
// span from the one answer, with nothing standing in for either side.
func TestTheClientReadsWhatTheHandlerAnswers(t *testing.T) {
	previous, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	previousPem, _ := previous.getSubjectPublicKeyInfo()
	currentPem, _ := current.getSubjectPublicKeyInfo()
	nextPem, _ := next.getSubjectPublicKeyInfo()
	rotation := at(t, "2026-08-31T00:00:00Z")
	week := 7 * 24 * time.Hour
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(nil)
	requests := 0
	handler := HandlerPublicKey(s)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	// The store is keyed by the host the request arrives on, which is the
	// creator domain the identifier carries.
	schedule := []DatedKey{
		{StartsAt: rotation.Add(-week), PublicKey: previousPem},
		{StartsAt: rotation, PublicKey: currentPem},
		{StartsAt: rotation.Add(week), PublicKey: nextPem},
	}
	s.SetPublicKeyStore(NewDatedPublicKeyStore(map[string][]DatedKey{
		"creator.test": schedule,
		strings.TrimPrefix(server.URL, "http://"): schedule,
	}))
	useServer(t, server.URL)

	first := signedAt(t, "creator.test", rotation.Add(3*24*time.Hour), current)
	if status := first.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("the identifier should verify against the key the handler answered with, got %v", status)
	}
	second := signedAt(t, "creator.test", rotation.Add(6*24*time.Hour), current)
	if status := second.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("a second identifier in the same week should verify, got %v", status)
	}
	if requests != 1 {
		t.Fatalf("the whole week should be held from the handler's one answer, got %d requests", requests)
	}
	late := signedAt(t, "creator.test", rotation.Add(5*time.Minute), previous)
	if status := late.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("an identifier signed with the earlier key just after the rotation should verify, got %v", status)
	}
	if requests != 2 {
		t.Fatalf("the earlier key should be asked for once, got %d requests", requests)
	}
	forged := signedAt(t, "creator.test", rotation.Add(3*24*time.Hour), next)
	if status := forged.SignatureStatusFromDomain("https"); status != SignatureInvalid {
		t.Fatalf("an identifier signed with a key not in force at its date should not verify, got %v", status)
	}
}

// keyPair is a new key pair and its public key in PEM form.
func keyPair(t *testing.T) (*Crypto, string) {
	t.Helper()
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.getSubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	return c, pem
}

// scheduleOfTwo stands in for a creator with two keys, the first in force
// from start until the rotation and the second from the rotation until end,
// or until further notice where end is nil. It records the date parameter of
// every request.
func scheduleOfTwo(t *testing.T, firstPem string, secondPem string, start time.Time, rotation time.Time, end *time.Time) (*httptest.Server, *[]string) {
	t.Helper()
	asked := &[]string{}
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			d := r.URL.Query().Get("date")
			*asked = append(*asked, d)
			m, err := strconv.ParseUint(d, 10, 32)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			moment := ioDateBase.Add(time.Duration(m) * time.Minute)
			if moment.Before(rotation) {
				writeKeyAnswer(t, w, true, firstPem, start, &rotation, moment)
				return
			}
			writeKeyAnswer(t, w, true, secondPem, rotation, end, moment)
		}))
	t.Cleanup(s.Close)
	return s, asked
}

// TestTheNeighbourIsAskedForByTheMinuteJustBeyondTheEdge checks that the
// neighbouring key is asked for by the minute just beyond the edge of the
// span the creator stated, not by a minute a fixed distance from the
// identifier, so a key in force for less than the drift allowance is still
// the one tried.
func TestTheNeighbourIsAskedForByTheMinuteJustBeyondTheEdge(t *testing.T) {
	first, firstPem := keyPair(t)
	_, secondPem := keyPair(t)
	start := at(t, "2026-08-24T00:00:00Z")
	rotation := at(t, "2026-08-31T00:00:00Z")
	end := at(t, "2026-09-07T00:00:00Z")
	s, asked := scheduleOfTwo(t, firstPem, secondPem, start, rotation, &end)
	useServer(t, s.URL)

	late := signedAt(t, "creator.test", rotation.Add(5*time.Minute), first)
	if status := late.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("an identifier signed with the earlier key just after the rotation should verify, got %v", status)
	}
	own := minutesSinceBase(rotation) + 5
	want := []string{
		strconv.FormatUint(uint64(own), 10),
		strconv.FormatUint(uint64(minutesSinceBase(rotation)-1), 10)}
	if strings.Join(*asked, " ") != strings.Join(want, " ") {
		t.Fatalf("the identifier's own minute and then the minute just before the span started should be asked for, got %v want %v", *asked, want)
	}
}

// TestAKeyStatedWithoutAnEndHasNoLaterEdge checks that a key the creator
// states a start for and no end is in force until further notice as far as
// the creator has said, so a live identifier dated just after that start
// which does not verify under it is checked against the key before it, even
// though the cache holds the key only up to the drift allowance behind now.
func TestAKeyStatedWithoutAnEndHasNoLaterEdge(t *testing.T) {
	first, firstPem := keyPair(t)
	_, secondPem := keyPair(t)
	rotation := dateFromMinutes(minutesSinceBase(time.Now().UTC()) - 5)
	start := rotation.Add(-7 * 24 * time.Hour)
	s, asked := scheduleOfTwo(t, firstPem, secondPem, start, rotation, nil)
	useServer(t, s.URL)

	live := signedAt(t, "creator.test", rotation.Add(2*time.Minute), first)
	if status := live.SignatureStatusFromDomain("https"); status != SignatureValid {
		t.Fatalf("a live identifier signed with the key before the current one should verify, got %v", status)
	}
	if len(*asked) != 2 {
		t.Fatalf("the current key and then the key before it should be asked for, got %d requests", len(*asked))
	}
}

// TestAKeyTheCreatorSaysWasNotInForceLeavesTheSignatureUnjudged checks that
// a creator whose own statement puts the identifier's date outside the span
// of the key it answered with has said that key did not sign at that date,
// so nothing verifying under it leaves the key unavailable rather than the
// signature not matching. A forgery dated inside the span is still reported
// as not matching.
func TestAKeyTheCreatorSaysWasNotInForceLeavesTheSignatureUnjudged(t *testing.T) {
	first, _ := keyPair(t)
	_, secondPem := keyPair(t)
	stranger, _ := keyPair(t)
	rotation := at(t, "2026-08-31T00:00:00Z")
	end := at(t, "2026-09-07T00:00:00Z")
	// A creator that ignores the date asked about and answers with the
	// current key and its span whatever the request. The answer is written
	// directly, because the checks a creator built on this package applies
	// before answering would refuse it for the moment asked about.
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PublicKeyResponse{
				Format: SpkiFormat, PublicKey: secondPem, ValidFrom: &rotation, ValidTo: &end})
		}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)

	earlier := signedAt(t, "creator.test", rotation.Add(-3*24*time.Hour), first)
	if status := earlier.SignatureStatusFromDomain("https"); status != KeyUnavailable {
		t.Fatalf("the key answered with was not in force at the identifier's date, so it should be KeyUnavailable, got %v", status)
	}
	valid, err := earlier.Verify("https")
	if valid {
		t.Fatal("the boolean form cannot say true for a key that was not in force")
	}
	var k *KeyFetchError
	if !errors.As(err, &k) || k.Status != KeyUnavailable {
		t.Fatalf("the boolean form should carry KeyUnavailable so its false does not read as a forgery, got %v", err)
	}
	forged := signedAt(t, "creator.test", rotation.Add(3*24*time.Hour), stranger)
	if status := forged.SignatureStatusFromDomain("https"); status != SignatureInvalid {
		t.Fatalf("a signature failing under the key in force at its date does not match, got %v", status)
	}
}

// TestAnAnswerThatIsNotTheJSONFormIsAKeyThatCannotBeRead checks that the PEM alone as text is reported as a key this package cannot read rather than used.
func TestAnAnswerThatIsNotTheJSONFormIsAKeyThatCannotBeRead(t *testing.T) {
	k := newKeyServer(t)
	pem := k.schedule[0].pem
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, pem)
	}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)
	if status := fixtureIdentifier(t).SignatureStatusFromDomain("https"); status != InvalidKey {
		t.Fatalf("the PEM alone should be reported as a key that cannot be read, got %v", status)
	}
}

// TestAnAnswerStatingAnotherFormatIsAKeyThatCannotBeRead checks that an
// answer whose format is not the one this package reads is refused as a key
// that cannot be read, whatever the key field holds.
func TestAnAnswerStatingAnotherFormatIsAKeyThatCannotBeRead(t *testing.T) {
	k := newKeyServer(t)
	pem := k.schedule[0].pem
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PublicKeyResponse{Format: "pkcs", PublicKey: pem})
	}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)
	if status := fixtureIdentifier(t).SignatureStatusFromDomain("https"); status != InvalidKey {
		t.Fatalf("an answer in another format should be reported as a key that cannot be read, got %v", status)
	}
}

// TestAnAnswerWhoseSpanEndsBeforeItStartsIsRefused checks that a creator
// whose schedule contradicts itself is refused by the client as well as by
// the checks a creator built on this package applies before answering.
func TestAnAnswerWhoseSpanEndsBeforeItStartsIsRefused(t *testing.T) {
	k := newKeyServer(t)
	pem := k.schedule[0].pem
	from := at(t, "2026-08-31T00:00:00Z")
	to := at(t, "2026-08-24T00:00:00Z")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PublicKeyResponse{Format: SpkiFormat, PublicKey: pem, ValidFrom: &from, ValidTo: &to})
	}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)
	if status := fixtureIdentifier(t).SignatureStatusFromDomain("https"); status != InvalidKey {
		t.Fatalf("a span that ends before it starts should be refused, got %v", status)
	}
	asked := from.Add(time.Hour)
	if _, err := NewPublicKeyResponse(pem, &KeyPeriod{PublicKey: pem, StartsAt: from, EndsAt: &to}, asked); err == nil {
		t.Fatal("a creator built on this package should refuse to answer with a span that ends before it starts")
	}
	if _, err := NewPublicKeyResponse("not a key", nil, asked); err == nil {
		t.Fatal("a creator built on this package should refuse to answer with a key that cannot be read")
	}
	if _, err := NewPublicKeyResponse(pem, &KeyPeriod{PublicKey: pem, StartsAt: asked.Add(time.Minute)}, asked); err == nil {
		t.Fatal("a creator built on this package should refuse to answer with a key that had not started")
	}
}

// TestManyGoroutinesVerifyingOneIdentifierMakeOneRequest checks that
// goroutines verifying the same identifier at the same moment make one
// request for its key between them, and every one of them gets the answer.
func TestManyGoroutinesVerifyingOneIdentifierMakeOneRequest(t *testing.T) {
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.getSubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	var requests int32
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&requests, 1)
			// Held long enough for every goroutine to arrive while the
			// request is under way.
			time.Sleep(300 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PublicKeyResponse{Format: SpkiFormat, PublicKey: pem})
		}))
	t.Cleanup(s.Close)
	useServer(t, s.URL)
	o := signedAt(t, "creator.test", at(t, "2026-08-31T12:00:00Z"), c)

	const callers = 16
	start := make(chan struct{})
	statuses := make(chan SignatureStatus, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses <- o.SignatureStatusFromDomain("https")
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != SignatureValid {
			t.Fatalf("every caller should get the key, got %v", status)
		}
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("%d callers arriving together should make one request, got %d", callers, got)
	}
}
