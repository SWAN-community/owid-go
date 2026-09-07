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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The key cache holds each key against the span of minutes the creator has
// confirmed it for, rather than against the minute of one identifier. The
// tests here drive fetchPublicKey against the stand in end point with
// identifiers dated in the past, so the cache reads each minute as itself
// rather than as now.

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
	k := newKeyServer(t)
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
	k := newKeyServer(t)
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
	k := newKeyServer(t)
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

// TestAFutureDateIsHeldAgainstNow checks that a date later than now is held
// against now, because a creator answers a future date with the key in force
// now and a key held against a minute the creator has not spoken for would be
// served for that minute after the creator had rotated. Two future dates
// therefore share one request.
func TestAFutureDateIsHeldAgainstNow(t *testing.T) {
	k := newKeyServer(t)
	useServer(t, k.server.URL)
	started := minutesSinceBase(time.Now().UTC())
	now := time.Now().UTC()
	pemAt(t, now.Add(7*24*time.Hour))
	pemAt(t, now.Add(14*24*time.Hour))
	if minutesSinceBase(time.Now().UTC()) != started {
		t.Skip("the minute changed during the test, so the calls were not all about the same now")
	}
	if len(k.dates) != 1 {
		t.Fatalf("two future dates are both now, so now should be asked about once, got %d requests", len(k.dates))
	}
}

// TestTheKeyCacheIsBounded checks that the cache does not grow without limit.
// The number of distinct keys a verifier is shown is chosen by whoever
// presents the identifiers rather than by this process, so the stand in
// creator here answers every minute with a different key, which is the worst
// a creator can do to the cache.
func TestTheKeyCacheIsBounded(t *testing.T) {
	requests := 0
	s := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests++
			fmt.Fprintf(w, "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n",
				r.URL.Query().Get("date"))
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
