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

	"github.com/SWAN-community/common-go"
)

// HandlerAddKeys adds a key to the signer associated with the domain.
func HandlerAddKeys(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Confirm access is allowed by the caller.
		if !s.access.GetAllowedHttp(w, r) {
			return
		}

		// Get the signer using the common method. This will handle any HTTP
		// failure responses.
		g := s.GetSignerHttp(w, r)
		if g == nil {
			return
		}

		// Create a new set of keys.
		k, err := newKeys()
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}

		// Add the new key to the store against the signer's domain.
		err = s.store.addKeys(g.Domain, k)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}

		// The store must be refreshed to retrieve the new key that was added
		// to the signer. Without this call the key won't become effective
		// until the process restarts.
		err = s.store.refresh()
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}

		// Check that the new key is available in storage and usable.
		n, err := s.store.GetSigner(g.Domain)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		f := false
		for _, i := range n.Keys {
			if i.equal(k) {
				f = true
				break
			}
		}
		if !f {
			common.ReturnServerError(
				w,
				fmt.Errorf("new key not found"))
			return
		}

		// The new key has been added to the storage
		common.SendString(
			w,
			fmt.Sprintf("New key added for signer '%s'", g.Domain))
	}
}
