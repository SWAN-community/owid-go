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
	"fmt"
	"net/http"
	"time"
)

// HandlerCreate generates and OWID. Key for this handler is the incoming
// domain name. i.e. example.com. Extract parameters and create the OWID which
//  is returned.
func HandlerCreate(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := createOWID(s, r)
		if err != nil {
			returnAPIError(s, w, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write([]byte(u))
	}
}

func createOWID(s *Services, r *http.Request) (string, error) {

	// Get creator associated with the request
	c, err := s.store.getCreator(r.Host)
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", fmt.Errorf("There is no creator associated "+
			"with the host %v", r.Host)
	}

	// Get signing key
	cry, err := NewCryptoSignOnly(c.privateKey)
	if err != nil {
		return "", err
	}

	// what is payload?
	payload := []byte("test")

	date := time.Now().UTC()

	// Generate signature of OWID
	signature, err := cry.Sign(date, payload)
	if err != nil {
		return "", err
	}

	// Create the OWID
	o, err := NewOwid(r.Host, signature, date, payload)
	if err != nil {
		return "", err
	}

	// Get the OWID as a base64 string
	owid, err := o.EncodeAsBase64()
	if err != nil {
		return "", err
	}

	return owid, nil
}
