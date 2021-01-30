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
)

// HandlerPublicKey returns the public key associated with the creator.
func HandlerPublicKey(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := s.store.GetCreator(r.Host)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		err = r.ParseForm()
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		var p string
		switch r.Form.Get("format") {
		case "pkcs":
			p = c.publicKey
			break
		case "spki":
			p, err = c.SubjectPublicKeyInfo()
			break
		default:
			err = fmt.Errorf(
				"Format parameter 'spki' or 'pkcs' must be provided")
			break
		}
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		b := []byte(p)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "private,max-age=1800")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
		_, err = w.Write(b)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
	}
}
