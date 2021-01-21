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

type verify struct {
	Valid bool `json:"valid"`
}

// HandlerVerify verifies the signature in the incoming OWID. If the method is
// POST and the content is binary data then the OWID is created using the
// FromByteArray method. Otherwise the OWID is constructed form the base 64
// encoded string in the owid parameter.
// Returns true if the OWID is valid, otherwise false.
func HandlerVerify(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var v verify
		p, o, err := verifyGetOWIDs(r)
		if err != nil {
			returnAPIError(s, w, err, http.StatusBadRequest)
			return
		}
		c, err := getCreatorFromRequest(s, r)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		v.Valid, err = c.Verify(o, p)
		if err != nil && err.Error() != "crypto/rsa: verification error" {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		j, err := json.Marshal(v)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(j)
	}
}

func verifyGetOWIDs(r *http.Request) (*OWID, *OWID, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, nil, err
	}
	if r.FormValue("owid") == "" {
		return nil, nil, fmt.Errorf("owid parameter must be provided")
	}
	var p *OWID
	if r.FormValue("parent") != "" {
		p, err = FromBase64(r.FormValue("parent"))
		if err != nil {
			return nil, nil, err
		}
	}
	o, err := FromBase64(r.FormValue("owid"))
	if err != nil {
		return nil, nil, err
	}
	return p, o, nil
}
