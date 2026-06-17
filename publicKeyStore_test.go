/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited (51degrees.com)
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
	"testing"
	"time"
)

// Out of order on purpose, to prove the selection sorts.
func testDatedKeys() []DatedKey {
	return []DatedKey{
		{Created: time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC), PublicKey: "k-0308"},
		{Created: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "k-0301"},
		{Created: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), PublicKey: "k-0315"},
	}
}

func pkDate(year int, month time.Month, day int) *time.Time {
	t := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return &t
}

func TestSelectPublicKeyBetweenKeysReturnsEarlier(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 3, 10)); got != "k-0308" {
		t.Fatalf("got %q, want k-0308", got)
	}
}

func TestSelectPublicKeyExactlyOnKey(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 3, 8)); got != "k-0308" {
		t.Fatalf("got %q, want k-0308", got)
	}
}

func TestSelectPublicKeyAfterNewestReturnsNewest(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 4, 1)); got != "k-0315" {
		t.Fatalf("got %q, want k-0315", got)
	}
}

func TestSelectPublicKeyBeforeOldestReturnsEmpty(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2020, 1, 2)); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestSelectPublicKeyNilDateReturnsNewest(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), nil); got != "k-0315" {
		t.Fatalf("got %q, want k-0315", got)
	}
}
