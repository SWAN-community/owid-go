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
	"net/http"
	"strconv"
	"time"
)

// HandlerPublicKey returns the public key associated with the creator. An
// optional date parameter, minutes since 2020-01-01 UTC, selects the key that
// was current at that date.
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
		p, err := s.publicKeyStore().GetPublicKey(r.Host, date)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		if p == "" {
			returnAPIError(
				s,
				w,
				fmt.Errorf("no signing key was active at the requested date"),
				http.StatusNotFound)
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
		w.Header().Set("Cache-Control", "max-age=60")
		sendResponse(s, w, "text/plain; charset=utf-8", []byte(p))
	}
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
	t := ioDateBase.Add(time.Duration(m) * time.Minute)
	return &t, nil
}
