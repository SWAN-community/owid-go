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
	"encoding/json"
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

// KeyPeriod is a signing public key together with the span it covers, being
// the moment it came into force and the moment the next key starts. EndsAt
// is nil where no later key has been scheduled, so the key is in force until
// further notice.
type KeyPeriod struct {
	PublicKey string     // Public key in PEM form
	StartsAt  time.Time  // UTC moment from which the key signs
	EndsAt    *time.Time // UTC moment the next key starts, or nil
}

// PublicKeyPeriodStore is a PublicKeyStore that also knows the span each key
// covers. The public key end point states the span in its response where the
// store can supply it, so a client holds the key for the whole span from one
// answer rather than asking again for every minute.
type PublicKeyPeriodStore interface {
	PublicKeyStore

	// GetPublicKeyPeriod returns the key in force at the date for the
	// domain, with the span it covers, or nil where no key was in force.
	// When date is nil the key in force now is returned.
	GetPublicKeyPeriod(domain string, date *time.Time) (*KeyPeriod, error)
}

// SpkiFormat is the one encoding of the key this package reads and writes, a
// Subject Public Key Info PEM. It is the value taken when a request names no
// format.
const SpkiFormat = "spki"

// PublicKeyResponse is the JSON body of the public key end point. It carries
// the key, the encoding the key is in, and the moments it is valid from and
// to, in UTC, so a client holds the key for the whole span from one answer
// rather than asking again for every minute. ValidFrom is nil where the
// creator does not know when the key started, and ValidTo is nil where no
// later key has been scheduled. The PEM alone as text is not a valid answer.
type PublicKeyResponse struct {
	Format    string     `json:"format"`    // The encoding of PublicKey, being the value the request asked for
	PublicKey string     `json:"publicKey"` // The public key in the encoding Format names
	ValidFrom *time.Time `json:"validFrom"` // UTC moment the key came into force
	ValidTo   *time.Time `json:"validTo"`   // UTC moment the next key starts
}

// NewPublicKeyResponse is the answer for the key in force at the moment
// asked about, with the span where the store knows it, checked before it is
// returned so that a creator never sends an answer it would itself refuse.
func NewPublicKeyResponse(pem string, period *KeyPeriod, asked time.Time) (PublicKeyResponse, error) {
	response := PublicKeyResponse{Format: SpkiFormat, PublicKey: pem}
	if period != nil {
		from := period.StartsAt.UTC()
		response.ValidFrom = &from
		if period.EndsAt != nil {
			to := period.EndsAt.UTC()
			response.ValidTo = &to
		}
	}
	if err := ValidatePublicKeyResponse(response, &asked); err != nil {
		return PublicKeyResponse{}, err
	}
	return response, nil
}

// ValidatePublicKeyResponse checks a public key answer the way both the
// creator that sends it and the client that reads it must. The format must be
// the one this package reads, or absent, and the key must be a public key in
// it, a key valid to a moment must be valid from an earlier one, and where
// the moment asked about is known the key must have come into force by then
// and, if it has an end, not have ended. A creator that fails this check has
// a fault in its schedule or its store, and answering with a 500 shows it up
// rather than passing it on.
func ValidatePublicKeyResponse(response PublicKeyResponse, asked *time.Time) error {
	if response.Format != "" && response.Format != SpkiFormat {
		return fmt.Errorf("the public key answer states a format this package does not read")
	}
	if response.PublicKey == "" {
		return fmt.Errorf("the public key answer holds no key")
	}
	if _, err := NewCryptoVerifyOnly(response.PublicKey); err != nil {
		return fmt.Errorf("the public key answer holds a key that cannot be read: %w", err)
	}
	if response.ValidTo != nil {
		if response.ValidFrom == nil {
			return fmt.Errorf("the public key answer states when the key ends but not when it started")
		}
		if !response.ValidTo.After(*response.ValidFrom) {
			return fmt.Errorf("the public key answer states a key that ends before it starts")
		}
	}
	if asked != nil {
		if response.ValidFrom != nil && response.ValidFrom.After(*asked) {
			return fmt.Errorf("the public key answer states a key that had not started at the moment asked about")
		}
		if response.ValidTo != nil && !response.ValidTo.After(*asked) {
			return fmt.Errorf("the public key answer states a key that had ended at the moment asked about")
		}
	}
	return nil
}

// ReadPublicKeyResponse reads a public key answer, returning the PEM and the
// span in minutes since 2020-01-01 UTC, the count the date parameter uses.
// The end is the minute the next key starts. Either is nil where the answer
// does not state it. An answer that is not the JSON form, the PEM alone
// among them, or that fails ValidatePublicKeyResponse, is an error.
func ReadPublicKeyResponse(body []byte) (string, *uint32, *uint32, error) {
	var answer PublicKeyResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		return "", nil, nil, fmt.Errorf("the public key answer is not the JSON form the specification requires: %w", err)
	}
	if err := ValidatePublicKeyResponse(answer, nil); err != nil {
		return "", nil, nil, err
	}
	return answer.PublicKey, minutesOf(answer.ValidFrom), minutesOf(answer.ValidTo), nil
}

// minutesOf is the moment as minutes since 2020-01-01 UTC, or nil where
// there is no moment or it is before the count begins.
func minutesOf(moment *time.Time) *uint32 {
	if moment == nil || moment.Before(ioDateBase) {
		return nil
	}
	minutes := minutesSinceBase(*moment)
	return &minutes
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

// GetPublicKeyPeriod returns the key that was in force at the date for the
// domain, with the span it covers.
func (s *DatedPublicKeyStore) GetPublicKeyPeriod(
	domain string,
	date *time.Time) (*KeyPeriod, error) {
	return selectPublicKeyPeriod(s.keys[domain], date), nil
}

// selectPublicKey returns the key in force at the date, being the key with
// the latest start at or before it, or the key in force now when date is
// nil. A date later than now is read as now, because a schedule is
// published ahead of time and a key that has not started has signed
// nothing. Returns an empty string when date predates every key, or when no
// key has started yet.
func selectPublicKey(keys []DatedKey, date *time.Time) string {
	period := selectPublicKeyPeriod(keys, date)
	if period == nil {
		return ""
	}
	return period.PublicKey
}

// selectPublicKeyPeriod is selectPublicKey together with the span the chosen
// key covers, which runs from its start to the earliest later start in the
// schedule, or on without end where there is none.
func selectPublicKeyPeriod(keys []DatedKey, date *time.Time) *KeyPeriod {
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
		return nil
	}
	period := &KeyPeriod{PublicKey: best.PublicKey, StartsAt: best.StartsAt}
	for i := range keys {
		k := &keys[i]
		if k.StartsAt.After(best.StartsAt) &&
			(period.EndsAt == nil || k.StartsAt.Before(*period.EndsAt)) {
			ends := k.StartsAt
			period.EndsAt = &ends
		}
	}
	return period
}
