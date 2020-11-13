/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited
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

type verify struct {
	Valid bool `json:"valid"`
}

// HandlerVerify verifies the signature in the incoming ID.
// Returns if the ID is valid.
// Decode the ID into an owid structure.
// Get the public key from the store.
func HandlerVerify(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			returnAPIError(s, w, err)
			return
		}

		owid := r.FormValue("owid")

		c, err := getCreatorFromRequest(s, r)
		if err != nil {
			returnAPIError(s, w, err)
			return
		}

		cry, err := NewCryptoVerifyOnly(c.publicKey)
		if err != nil {
			returnAPIError(s, w, err)
			return
		}

		v, err := cry.Verify(owid)
		if err != nil {
			returnAPIError(s, w, err)
			return
		}

		var vfy verify
		vfy.Valid = v

		json, err := json.Marshal(vfy)

		if err != nil {
			returnAPIError(s, w, err)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(json)
	}
}
