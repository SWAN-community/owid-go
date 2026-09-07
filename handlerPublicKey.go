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
	"net/http"
	"strconv"
	"time"
)

// HandlerPublicKey returns the public key associated with the creator. An
// optional date parameter, minutes since 2020-01-01 UTC, selects the key that
// was current at that date. The answer is a PublicKeyResponse as JSON, which
// states the moments the key is valid from and to where the store knows them,
// so a client holds the key for the whole span from one answer. The answer is
// checked before it is sent, and a store whose key cannot be read or whose
// schedule contradicts itself is reported as a server error rather than
// passed on.
func HandlerPublicKey(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		if !s.authorize(w, r) {
			return
		}
		date, err := parsePublicKeyDate(r)
		if err != nil {
			returnAPIError(s, w, err, http.StatusBadRequest)
			return
		}
		p, period, err := publicKeyWithPeriod(s.publicKeyStore(), r.Host, date)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		if p == "" {
			msg := "no signing key is available"
			if date != nil {
				msg = "no signing key was active at the requested date"
			}
			returnAPIError(s, w, fmt.Errorf(msg), http.StatusNotFound)
			return
		}
		switch r.Form.Get("format") {
		case "pkcs":
			// p already holds the PEM as stored.
		case "spki":
			var cry *Crypto
			cry, err = NewCryptoVerifyOnly(p)
			if err == nil {
				p, err = cry.getSubjectPublicKeyInfo()
			}
		default:
			err = fmt.Errorf(
				"format parameter 'spki' or 'pkcs' must be provided")
		}
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		asked := time.Now().UTC()
		if date != nil && date.Before(asked) {
			asked = *date
		}
		response, err := NewPublicKeyResponse(p, period, asked)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		body, err := json.Marshal(response)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		sendResponse(s, w, "application/json; charset=utf-8", body)
	}
}

// publicKeyWithPeriod asks the store for the key in force at the date, and for
// the span it covers where the store knows it.
func publicKeyWithPeriod(
	store PublicKeyStore,
	domain string,
	date *time.Time) (string, *KeyPeriod, error) {
	if periods, ok := store.(PublicKeyPeriodStore); ok {
		period, err := periods.GetPublicKeyPeriod(domain, date)
		if err != nil || period == nil {
			return "", nil, err
		}
		return period.PublicKey, period, nil
	}
	p, err := store.GetPublicKey(domain, date)
	return p, nil, err
}

// parsePublicKeyDate reads the optional date parameter, the number of minutes
// since 2020-01-01 UTC, and returns the corresponding time. It returns nil
// when the parameter is absent.
func parsePublicKeyDate(r *http.Request) (*time.Time, error) {
	v := r.Form.Get("date")
	if v == "" {
		return nil, nil
	}
	m, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, fmt.Errorf(
			"date must be the number of minutes since 2020-01-01 UTC " +
				"as an unsigned 32-bit integer")
	}
	t := dateFromMinutes(uint32(m))
	return &t, nil
}
