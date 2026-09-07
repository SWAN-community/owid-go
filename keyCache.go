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

// heldKey is one key a creator has answered with, and the span of minutes
// the creator has confirmed it was in force for.
//
// A creator's key is in force from the start of its period until the next
// key starts, so a key the creator confirms at two minutes was in force at
// every minute between them. The span grows as the creator confirms the same
// key for more minutes, and an identifier dated inside it is verified without
// a request.
type heldKey struct {
	pem   string // The key in PEM form, as the creator served it
	first uint32 // The earliest minute the creator has confirmed the key for
	last  uint32 // The latest minute the creator has confirmed the key for
}

// covers says whether the minute lies within the confirmed span.
func (k *heldKey) covers(minute uint32) bool {
	return k.first <= minute && minute <= k.last
}

// keyCache holds keys already fetched, by the creator's key end point, which
// is the key URL without its date. Each end point holds the keys the creator
// has answered with, each with the span of minutes the creator has confirmed
// it for.
//
// The key URL carries the date of the identifier being verified, in minutes,
// and a creator's key changes on the order of a week. Keyed by the whole URL,
// as this cache once was, two identifiers signed a minute apart never shared
// an entry, so a hundred identifiers over a hundred minutes made a hundred
// requests for one key. Keyed by end point and span, an identifier dated
// between two minutes the creator has already answered for is verified
// without a request. Only a key that arrived is held; a failure is asked
// again next time.
var keyCache = struct {
	sync.Mutex
	held  map[string][]*heldKey
	count int // How many keys are held across every end point
}{held: map[string][]*heldKey{}}

// cachedKey returns the key held for the URL, if the creator has confirmed
// one for the minute the URL names.
func cachedKey(url string) (string, bool) {
	endPoint, minute := endPointAndMinute(url)
	keyCache.Lock()
	defer keyCache.Unlock()
	for _, key := range keyCache.held[endPoint] {
		if key.covers(minute) {
			return key.pem, true
		}
	}
	return "", false
}

// rememberKey records that the creator answered the URL with the key.
//
// A key already held for the end point has its span widened to take in the
// minute. A key not held before is added, emptying the cache first when it is
// full, because the cache must not grow on the input of whoever presents the
// identifiers.
func rememberKey(url string, pem string) {
	endPoint, minute := endPointAndMinute(url)
	keyCache.Lock()
	defer keyCache.Unlock()
	keys := keyCache.held[endPoint]
	for _, key := range keys {
		if key.pem == pem && widen(keys, key, minute) {
			return
		}
	}
	if keyCache.count >= maximumCachedKeys {
		keyCache.held = map[string][]*heldKey{}
		keyCache.count = 0
		keys = nil
	}
	keyCache.held[endPoint] = append(keys,
		&heldKey{pem: pem, first: minute, last: minute})
	keyCache.count++
}

// widen widens the span of a held key to take in the minute, and says
// whether the minute is now within it.
//
// The span is not widened across a minute the creator has answered with
// another key for, because that would mean the creator had gone back to a
// key it had left, and the minutes between the two spans are then not this
// key's to claim. The key is held again as a separate span instead.
func widen(keys []*heldKey, key *heldKey, minute uint32) bool {
	if key.covers(minute) {
		return true
	}
	from, to := key.first, key.last
	if minute < from {
		from = minute
	}
	if minute > to {
		to = minute
	}
	for _, other := range keys {
		if other != key && other.last > from && other.first < to {
			return false
		}
	}
	if minute < key.first {
		key.first = minute
	} else {
		key.last = minute
	}
	return true
}

// endPointAndMinute splits a key URL into the end point being asked, which
// is the URL without its query, and the minute the cache reads it as asking
// about.
//
// The minute is the date parameter where the URL carries one, and otherwise
// now, because a creator answers a request without a date with the key in
// force now. A date later than now is read as now as well, because that is
// how a creator reads it. A schedule is published ahead of time and a key
// that has not started has signed nothing, so the creator answers a future
// date with the key in force now, and that answer must be held against now
// rather than against a minute the creator has not spoken for. Held against
// the future minute, the key would still be served for that minute after the
// creator had rotated, and a genuine identifier signed then would read as not
// matching.
func endPointAndMinute(url string) (string, uint32) {
	now := minutesSinceBase(time.Now().UTC())
	endPoint, query, _ := strings.Cut(url, "?")
	for _, pair := range strings.Split(query, "&") {
		if strings.HasPrefix(pair, "date=") {
			minute, err := strconv.ParseUint(
				strings.TrimPrefix(pair, "date="), 10, 32)
			if err != nil || uint32(minute) > now {
				return endPoint, now
			}
			return endPoint, uint32(minute)
		}
	}
	return endPoint, now
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
	defer keyCache.Unlock()
	keyCache.held = map[string][]*heldKey{}
	keyCache.count = 0
}
