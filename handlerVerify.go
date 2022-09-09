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
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/SWAN-community/common-go"
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
		g := s.GetSignerHttp(w, r)
		if g == nil {
			return
		}
		o := verifyGetOWIDAndData(w, r)
		if o == nil {
			return
		}
		var err error
		v.Valid, err = g.Verify(o)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		j, err := json.Marshal(v)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		common.SendJS(w, j)
	}
}

func verifyGetOWIDAndData(w http.ResponseWriter, r *http.Request) *OWID {
	err := r.ParseForm()
	if err != nil {
		common.ReturnServerError(w, err)
		return nil
	}
	if r.FormValue("owid") == "" {
		common.ReturnApplicationError(w, &common.HttpError{
			Request: r,
			Code:    http.StatusBadRequest,
			Error:   err,
			Message: "owid parameter must be provided"})
		return nil
	}
	if r.FormValue("data") == "" {
		common.ReturnApplicationError(w, &common.HttpError{
			Request: r,
			Code:    http.StatusBadRequest,
			Error:   err,
			Message: "data parameter must be provided"})
		return nil
	}
	d, err := base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		common.ReturnApplicationError(w, &common.HttpError{
			Request: r,
			Code:    http.StatusBadRequest,
			Error:   err,
			Message: "data not valid"})
		return nil
	}
	o, err := FromBase64(r.FormValue("owid"), &ByteArray{Data: d})
	if err != nil {
		common.ReturnApplicationError(w, &common.HttpError{
			Request: r,
			Code:    http.StatusBadRequest,
			Error:   err,
			Message: "could not generate OWID"})
		return nil
	}
	err = o.Validate()
	if err != nil {
		common.ReturnApplicationError(w, &common.HttpError{
			Request: r,
			Code:    http.StatusBadRequest,
			Error:   err,
			Message: "owid not valid"})
		return nil
	}
	return o
}
