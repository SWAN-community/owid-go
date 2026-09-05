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

// Out of order on purpose, to prove the selection sorts. Every start is in
// the past, so the key in force now is the last of them.
func testDatedKeys() []DatedKey {
	return []DatedKey{
		{StartsAt: time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC), PublicKey: "k-0308"},
		{StartsAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "k-0301"},
		{StartsAt: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), PublicKey: "k-0315"},
	}
}

func pkDate(year int, month time.Month, day int) *time.Time {
	t := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	return &t
}

func TestSelectPublicKeyBetweenStartsReturnsKeyInForce(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 3, 10)); got != "k-0308" {
		t.Fatalf("got %q, want k-0308", got)
	}
}

// The start belongs to the key that is starting, and the minute before it
// belongs to the key before.
func TestSelectPublicKeyExactlyOnStartReturnsThatKey(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 3, 8)); got != "k-0308" {
		t.Fatalf("got %q, want k-0308", got)
	}
	before := time.Date(2026, 3, 7, 23, 59, 0, 0, time.UTC)
	if got := selectPublicKey(testDatedKeys(), &before); got != "k-0301" {
		t.Fatalf("got %q, want k-0301", got)
	}
}

func TestSelectPublicKeyAfterLastStartReturnsLastKey(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2026, 4, 1)); got != "k-0315" {
		t.Fatalf("got %q, want k-0315", got)
	}
}

func TestSelectPublicKeyBeforeOldestReturnsEmpty(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), pkDate(2020, 1, 2)); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestSelectPublicKeyNilDateReturnsKeyInForceNow(t *testing.T) {
	if got := selectPublicKey(testDatedKeys(), nil); got != "k-0315" {
		t.Fatalf("got %q, want k-0315", got)
	}
}

// A schedule published ahead of time holds keys that have not started. A
// request with no date is answered with the key in force now and never
// with one of those, and a date later than now is read as now.
func TestSelectPublicKeyNeverReturnsAKeyThatHasNotStarted(t *testing.T) {
	now := time.Now().UTC()
	keys := []DatedKey{
		{StartsAt: now.Add(-7 * 24 * time.Hour), PublicKey: "in-force"},
		{StartsAt: now.Add(7 * 24 * time.Hour), PublicKey: "not-started"},
		{StartsAt: now.Add(14 * 24 * time.Hour), PublicKey: "not-started-either"},
	}
	if got := selectPublicKey(keys, nil); got != "in-force" {
		t.Fatalf("nil date: got %q, want in-force", got)
	}
	future := now.Add(30 * 24 * time.Hour)
	if got := selectPublicKey(keys, &future); got != "in-force" {
		t.Fatalf("future date: got %q, want in-force", got)
	}
	nothingStarted := []DatedKey{keys[1], keys[2]}
	if got := selectPublicKey(nothingStarted, nil); got != "" {
		t.Fatalf("nothing started: got %q, want empty", got)
	}
}

// The published 51d.es schedule through the store, with the genuine
// identifier. The store must pick the key that verifies it, which is the
// one starting 31 August 2026, and not the newest generated key, which was
// written in a batch on 1 September and starts on 7 September.
func TestSelectPublicKeyPicksTheKeyThatSignedTheFixture(t *testing.T) {
	o := fixtureIdentifier(t)
	var keys []DatedKey
	for _, k := range fixtureSchedule(t) {
		keys = append(keys, DatedKey{StartsAt: k.startsAt, PublicKey: k.pem})
	}
	date := o.Date()
	pem := selectPublicKey(keys, &date)
	if pem == "" {
		t.Fatal("the schedule should cover the identifier's date")
	}
	if got := o.SignatureStatusWithPublicKey(pem); got != SignatureValid {
		t.Fatalf("the selected key should verify the identifier, got %s", got)
	}
}
