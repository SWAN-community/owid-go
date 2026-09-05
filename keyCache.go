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
	"sync"
	"time"
)

// keyFetchTimeout bounds a key fetch, so a creator that accepts the
// connection and never answers is reported as a key that could not be
// obtained rather than left hanging.
const keyFetchTimeout = 10 * time.Second

// maximumCachedKeys is the most keys held before the cache is emptied and
// filled again. The key is the whole URL, which carries the identifier's
// date, so a verifier that sees many creators and many periods would
// otherwise grow the cache for as long as the process runs.
const maximumCachedKeys = 1024

// keyCache holds keys already fetched, against the URL each came from. The
// URL names the domain, the version and the minute, and the key a creator
// published for a minute in the past does not change, so a fetched key
// never goes stale. Only a key that arrived is held; a failure is asked
// again next time.
var keyCache = struct {
	sync.Mutex
	held map[string]string
}{held: map[string]string{}}

// cachedKey returns the key held for the URL, if there is one.
func cachedKey(url string) (string, bool) {
	keyCache.Lock()
	defer keyCache.Unlock()
	pem, held := keyCache.held[url]
	return pem, held
}

// rememberKey holds the key against the URL it came from.
func rememberKey(url string, pem string) {
	keyCache.Lock()
	defer keyCache.Unlock()
	if len(keyCache.held) >= maximumCachedKeys {
		keyCache.held = map[string]string{}
	}
	keyCache.held[url] = pem
}

// ClearKeyCache empties the keys already fetched. Provided so that a long
// running process can release the memory, and so that a test can start from
// a known state.
func ClearKeyCache() {
	keyCache.Lock()
	defer keyCache.Unlock()
	keyCache.held = map[string]string{}
}
