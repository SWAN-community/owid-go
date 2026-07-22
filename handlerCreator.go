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
)

// PublicCreator used by a supply chain partner to cache the publicKey
// associated with the domain so that they do not need to call the end points to
// verify a signature. For example; a request is received with OWIDs and those
// OWIDs need to be verified before the bid is processed.
type PublicCreator struct {
	Domain        string `json:"domain"`        // The domain that the name and key relate to
	Name          string `json:"name"`          // Common name of the creator
	PublicKeySPKI string `json:"publicKeySPKI"` // The public key in SPKI form
	ContractURL   string `json:"contractURL"`   // URL with the T&Cs associated with the creation of the data in the OWID
}

// HandlerCreator Returns the public information associated with the creator.
// An optional date parameter, minutes since 2020-01-01 UTC, selects the key
// that was current at that date, matching the public-key end point.
func HandlerCreator(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		if !s.authorize(w, r) {
			return
		}
		c, err := s.store.GetCreator(r.Host)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		date, err := parsePublicKeyDate(r)
		if err != nil {
			returnAPIError(s, w, err, http.StatusBadRequest)
			return
		}
		key, err := s.publicKeyStore().GetPublicKey(r.Host, date)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		if key == "" {
			msg := "no signing key is available"
			if date != nil {
				msg = "no signing key was active at the requested date"
			}
			returnAPIError(s, w, fmt.Errorf(msg), http.StatusNotFound)
			return
		}
		pc, err := publicCreator(c, key)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		u, err := json.Marshal(pc)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		sendResponse(s, w, "application/json; charset=utf-8", u)
	}
}

// publicCreator builds the creator response, reporting the selected key in
// SPKI form. key is the PEM as held by the public key store.
func publicCreator(c *Creator, key string) (*PublicCreator, error) {
	cry, err := NewCryptoVerifyOnly(key)
	if err != nil {
		return nil, err
	}
	spki, err := cry.getSubjectPublicKeyInfo()
	if err != nil {
		return nil, err
	}
	var p PublicCreator
	p.PublicKeySPKI = spki
	p.Domain = c.domain
	p.Name = c.name
	p.ContractURL = c.contractURL
	return &p, nil
}
