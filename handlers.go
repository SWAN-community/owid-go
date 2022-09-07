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

// AddHandlers to the http default mux for shared web state.
func AddHandlers(s *Services) {
	http.HandleFunc("/owid/register", HandlerRegister(s))
	http.HandleFunc("/owid/addkeys", HandlerAddKeys(s))
	for _, i := range owidVersions {
		b := fmt.Sprintf("/owid/api/v%d/", i)
		http.HandleFunc(b+"signer", HandlerSigner(s))
		http.HandleFunc(b+"verify", HandlerVerify(s))
		if s.config.Debug {
			http.HandleFunc(b+"owids", HandlerSigners(s))
		}
	}
}

// getSigner for the request writing an error to the response if there is no
// signer for the host associated with the request.
func (s *Services) getSigner(w http.ResponseWriter, r *http.Request) *Signer {
	g, err := s.store.GetSigner(r.Host)
	if err != nil {
		common.ReturnServerError(w, err)
		return nil
	}
	if g == nil {
		common.ReturnApplicationError(w, &common.HttpError{
			// Log this application error as it indicates the hosting
			// environment is misconfigured. The request should never have
			// reached the application.
			Log:     true,
			Request: r,
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("no signer available for '%s'", r.Host),
			Error: fmt.Errorf(
				"use register handler to create signer for domain '%s'",
				r.Host)})
		return nil
	}
	return g
}
