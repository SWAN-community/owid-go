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
	"strconv"
	"strings"
	"sync"
	"time"
)

// keyFetchTimeout bounds a key fetch, so a creator that accepts the
// connection and never answers is reported as a key that could not be
// obtained rather than left hanging.
const keyFetchTimeout = 10 * time.Second

// maximumCachedKeys is the most keys held, across every creator, before the
// cache is emptied and filled again. The domains and dates asked about come
// from the identifiers presented to this process, so a verifier that sees
// many creators and many periods would otherwise grow the cache for as long
// as the process runs.
const maximumCachedKeys = 1024

// clockDriftAllowanceMinutes is how far a creator's clock may run ahead of or
// behind this one's.
//
// It is used in two places. A creator that does not state the span of the key
// it answers with reads a date later than its own now as now, so within this
// window of now this process cannot tell whether the creator read the minute
// as its past or as its present, and nothing learned from such an answer is
// held or served. And a creator's signing machines may not agree with the
// creator's own schedule to the minute, so an identifier dated within this
// window of a key's edge that does not verify under that key is checked
// against the neighbouring key before it is reported as not matching.
const clockDriftAllowanceMinutes = 15

// heldKey is one key a creator has answered with, and the span of minutes the
// key is known to cover.
//
// A creator's key is in force from the start of its period until the next key
// starts, so a key the creator confirms at two minutes was in force at every
// minute between them. Where the creator stated the span in its answer the
// span is explicit and complete, and an identifier dated anywhere inside it
// is verified without a request. Otherwise the span grows as the creator
// confirms the same key for more minutes.
type heldKey struct {
	pem      string // The key in PEM form, as the creator served it
	first    uint32 // The earliest minute the key is known to cover
	last     uint32 // The latest minute the key is known to cover
	explicit bool   // Whether the creator stated the whole span itself
}

// covers says whether the minute lies within the known span.
func (k *heldKey) covers(minute uint32) bool {
	return k.first <= minute && minute <= k.last
}

// keyAnswer is what the cache or a fetch answers with: the key, and where it
// is known, the span of minutes the key covers, so that a caller can tell
// whether the identifier it is checking sits near the edge of the span.
type keyAnswer struct {
	pem   string
	first uint32
	last  uint32
	known bool // Whether first and last say anything
}

// keyCache holds keys already fetched, by the creator's key end point, which
// is the key URL without its date. Each end point holds the keys the creator
// has answered with, each with the span of minutes it is known to cover.
//
// The key URL carries the date of the identifier being verified, in minutes,
// and a creator's key changes on the order of a week. Keyed by end point and span rather than by the whole URL, an identifier dated
// inside a span the creator has stated or confirmed is verified without a
// request. Only a key that arrived is held; a failure is asked again next
// time.
var keyCache = struct {
	sync.Mutex
	held  map[string][]*heldKey
	count int // How many keys are held across every end point
}{held: map[string][]*heldKey{}}

// cachedKey returns the key held for the URL, if one is known to cover the
// minute the URL names.
func cachedKey(url string) (keyAnswer, bool) {
	endPoint, minute, dated, recent := endPointAndMinute(url)
	if !dated {
		return keyAnswer{}, false
	}
	keyCache.Lock()
	defer keyCache.Unlock()
	for _, key := range keyCache.held[endPoint] {
		// A minute within the drift allowance of now is only served where
		// the creator itself stated the span, because a span confirmed
		// minute by minute says nothing certain about such a minute.
		if key.covers(minute) && (key.explicit || !recent) {
			return keyAnswer{pem: key.pem, first: key.first, last: key.last, known: true}, true
		}
	}
	return keyAnswer{}, false
}

// rememberKey records the creator's answer to the URL, being the key and,
// where the creator stated it in its JSON answer, the span the key covers as
// the minute it came into force and the minute the next key starts. It
// returns the key together with the span it is now known to cover.
//
// With both the start and the end the whole span is held as the creator's
// own statement. With the start alone the key is held from the start up to
// the drift allowance behind now, because no later key can have started
// before then. With neither the minute asked about is held on its own, as
// long as it is not within the drift allowance of now. A key already held
// for the end point has its span widened to take in the new one. A key not
// held before is added, emptying the cache first when it is full, because
// the cache must not grow on the input of whoever presents the identifiers.
func rememberKey(url string, pem string, start *uint32, end *uint32) keyAnswer {
	endPoint, minute, dated, recent := endPointAndMinute(url)
	first, last, explicit, hold := spanToHold(minute, dated, recent, start, end)
	if !hold {
		return keyAnswer{pem: pem}
	}
	keyCache.Lock()
	defer keyCache.Unlock()
	keys := keyCache.held[endPoint]
	for _, key := range keys {
		if key.pem == pem {
			if widen(keys, key, first, last) {
				key.explicit = key.explicit || explicit
				return keyAnswer{pem: pem, first: key.first, last: key.last, known: true}
			}
			// The creator has answered with another key inside this span
			// before, which it does not do unless it went back to a key it
			// had left. Nothing more is held about this key.
			return keyAnswer{pem: pem}
		}
	}
	for _, other := range keys {
		if other.last >= first && other.first <= last {
			return keyAnswer{pem: pem}
		}
	}
	if keyCache.count >= maximumCachedKeys {
		keyCache.held = map[string][]*heldKey{}
		keyCache.count = 0
		keys = nil
	}
	keyCache.held[endPoint] = append(keys,
		&heldKey{pem: pem, first: first, last: last, explicit: explicit})
	keyCache.count++
	return keyAnswer{pem: pem, first: first, last: last, known: true}
}

// spanToHold works out the span to hold a key against from the creator's
// answer, and whether anything is to be held at all. See rememberKey.
func spanToHold(minute uint32, dated bool, recent bool, start *uint32, end *uint32) (uint32, uint32, bool, bool) {
	if start != nil && end != nil {
		if *end <= *start {
			// A span that ends before it starts is not a statement about
			// anything, so it is read as if the end had not been given.
			return spanToHold(minute, dated, recent, start, nil)
		}
		return *start, *end - 1, true, true
	}
	now := minutesSinceBase(time.Now().UTC())
	if start != nil {
		last := *start
		if now >= clockDriftAllowanceMinutes && now-clockDriftAllowanceMinutes > last {
			last = now - clockDriftAllowanceMinutes
		}
		return *start, last, false, true
	}
	if dated && !recent {
		return minute, minute, false, true
	}
	return 0, 0, false, false
}

// widen widens the span of a held key to take in the span given, and says
// whether it did.
//
// The span is not widened across a minute the creator has answered with
// another key for, because that would mean the creator had gone back to a
// key it had left, and the minutes between the two spans are then not this
// key's to claim.
func widen(keys []*heldKey, key *heldKey, first uint32, last uint32) bool {
	if first > key.first {
		first = key.first
	}
	if last < key.last {
		last = key.last
	}
	for _, other := range keys {
		if other != key && other.last >= first && other.first <= last {
			return false
		}
	}
	key.first, key.last = first, last
	return true
}

// endPointAndMinute splits a key URL into the end point being asked, which is
// the URL without its query, and the minute it asks about. The third result
// is false where the URL names no minute, and the fourth is true where the
// minute is within the drift allowance of now or later, which is a minute a
// creator that does not state its spans may have read as its present rather
// than as the minute named.
func endPointAndMinute(url string) (string, uint32, bool, bool) {
	now := minutesSinceBase(time.Now().UTC())
	endPoint, query, _ := strings.Cut(url, "?")
	for _, pair := range strings.Split(query, "&") {
		if strings.HasPrefix(pair, "date=") {
			minute, err := strconv.ParseUint(
				strings.TrimPrefix(pair, "date="), 10, 32)
			if err != nil {
				return endPoint, 0, false, false
			}
			recent := now < clockDriftAllowanceMinutes ||
				uint32(minute) > now-clockDriftAllowanceMinutes
			return endPoint, uint32(minute), true, recent
		}
	}
	return endPoint, 0, false, false
}

// inFlightKey is one fetch under way, shared between the caller making it and
// every caller that asked for the same URL while it ran, so that callers
// arriving together make one request between them rather than one each.
type inFlightKey struct {
	done   chan struct{} // Closed once the fetch has ended
	answer keyAnswer
	err    error
}

// inFlight holds the fetches under way, by the URL asked for. An entry is
// removed when its fetch ends, whatever the outcome, so a failure is never
// handed to a later caller.
var inFlight = struct {
	sync.Mutex
	fetches map[string]*inFlightKey
}{fetches: map[string]*inFlightKey{}}

// shareFetch returns the fetch under way for the URL and false, or registers
// a new one and returns it with true, meaning the caller is the one that
// performs the request and must call finish.
func shareFetch(url string) (*inFlightKey, bool) {
	inFlight.Lock()
	defer inFlight.Unlock()
	if fetch, under := inFlight.fetches[url]; under {
		return fetch, false
	}
	fetch := &inFlightKey{done: make(chan struct{})}
	inFlight.fetches[url] = fetch
	return fetch, true
}

// finish records the outcome of the fetch and wakes every caller waiting on
// it. Only this fetch is removed from those under way, never one that
// replaced it after the cache was emptied.
func (f *inFlightKey) finish(url string, answer keyAnswer, err error) {
	inFlight.Lock()
	if inFlight.fetches[url] == f {
		delete(inFlight.fetches, url)
	}
	inFlight.Unlock()
	f.answer = answer
	f.err = err
	close(f.done)
}

// cachedKeyCount is how many keys the cache holds, for the tests.
func cachedKeyCount() int {
	keyCache.Lock()
	defer keyCache.Unlock()
	return keyCache.count
}

// ClearKeyCache empties the keys already fetched, so that the next
// verification of any identifier asks the creator again. This is how a long
// running process drops a key it has learned it should no longer trust, after
// a creator rotates its key following a compromise, and how a test starts
// from a known state.
func ClearKeyCache() {
	keyCache.Lock()
	keyCache.held = map[string][]*heldKey{}
	keyCache.count = 0
	keyCache.Unlock()
	// The fetches under way are forgotten too, so the next caller for any
	// key starts a request of its own. A fetch already running is not
	// stopped, and the callers waiting on it still receive its answer.
	inFlight.Lock()
	inFlight.fetches = map[string]*inFlightKey{}
	inFlight.Unlock()
}
