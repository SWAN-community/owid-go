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

// HandlerCreate generates and OWID. Key for this handler is the incoming
// domain name. i.e. example.com. Extract parameters and create the OWID which
//  is returned.
func HandlerCreate(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := createOWID(s, r)
		if err != nil {
			returnAPIError(s, w, err, http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write([]byte(u))
	}
}

func createOWID(s *Services, r *http.Request) (string, error) {

	// Get creator associated with the request
	c, err := s.store.GetCreator(r.Host)
	if err != nil {
		return "", err
	}
	if c == nil {
		return "",
			fmt.Errorf("There is no creator associated with the host '%s'",
				r.Host)
	}

	return c.CreateOWID("test")
}
