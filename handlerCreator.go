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
}

// HandlerCreator Returns the public information associated with the creator.
func HandlerCreator(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.store.GetCreator(r.Host)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		pc, err := publicCreator(c)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		u, err := json.Marshal(pc)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "private,max-age=1800")
		w.Write(u)
	}
}

func publicCreator(c *Creator) (*PublicCreator, error) {
	var err error
	var p PublicCreator
	p.PublicKeySPKI, err = c.SubjectPublicKeyInfo()
	if err != nil {
		return nil, err
	}
	p.Domain = c.domain
	p.Name = c.name
	return &p, nil
}
