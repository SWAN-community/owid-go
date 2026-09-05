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
	"fmt"
	"time"
)

// PublicKeyStore provides the signing public key (PEM) for a creator,
// optionally the key that was current at a given date. Implement this to
// serve historical keys for a creator that rotates its signing key.
type PublicKeyStore interface {

	// GetPublicKey returns the public key in PEM form for the domain. When
	// date is not nil the key that was current at that date is returned. An
	// empty string indicates no key was active at the requested date.
	GetPublicKey(domain string, date *time.Time) (string, error)
}

// DatedKey is a signing public key together with the moment it comes into
// force. A key stays in force until the next key starts, so the last key of
// a schedule covers every date after it.
//
// StartsAt is the schedule position and not the moment the key material was
// generated. The two only agree whilst keys are generated one period at a
// time. A creator that writes several future periods in one run breaks the
// agreement, and selecting on the moment of generation then returns a key
// whose period has not started, so every genuine identifier of that period
// reads as forged. That moment is deliberately not held here at all.
type DatedKey struct {
	StartsAt  time.Time // UTC moment from which the key signs
	PublicKey string    // Public key in PEM form
}

// creatorPublicKeyStore is the default PublicKeyStore. It serves the single
// key held by the creator store and ignores the date, which suits a creator
// that uses one long-lived signing key.
type creatorPublicKeyStore struct {
	store Store
}

// GetPublicKey returns the creator's single public key for the domain.
func (s *creatorPublicKeyStore) GetPublicKey(
	domain string,
	date *time.Time) (string, error) {
	c, err := s.store.GetCreator(domain)
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", fmt.Errorf("no creator for domain '%s'", domain)
	}
	return c.publicKey, nil
}

// DatedPublicKeyStore serves historical keys per domain, applying the
// selection rule the 51Degrees cloud applies: the key in force at the
// requested date, being the key with the latest start at or before it.
type DatedPublicKeyStore struct {
	keys map[string][]DatedKey
}

// NewDatedPublicKeyStore returns a PublicKeyStore over the supplied keys,
// keyed by domain. The keys for a domain may be in any order.
func NewDatedPublicKeyStore(keys map[string][]DatedKey) *DatedPublicKeyStore {
	return &DatedPublicKeyStore{keys: keys}
}

// GetPublicKey returns the key that was current at the date for the domain.
func (s *DatedPublicKeyStore) GetPublicKey(
	domain string,
	date *time.Time) (string, error) {
	return selectPublicKey(s.keys[domain], date), nil
}

// selectPublicKey returns the key in force at the date, being the key with
// the latest start at or before it, or the key in force now when date is
// nil. A date later than now is read as now, because a schedule is
// published ahead of time and a key that has not started has signed
// nothing. Returns an empty string when date predates every key, or when no
// key has started yet.
func selectPublicKey(keys []DatedKey, date *time.Time) string {
	at := time.Now().UTC()
	if date != nil && date.Before(at) {
		at = *date
	}
	var best *DatedKey
	for i := range keys {
		k := &keys[i]
		if k.StartsAt.After(at) {
			continue
		}
		if best == nil || k.StartsAt.After(best.StartsAt) {
			best = k
		}
	}
	if best == nil {
		return ""
	}
	return best.PublicKey
}
