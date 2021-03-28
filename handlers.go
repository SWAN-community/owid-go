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

// AddHandlers to the http default mux for shared web state.
func AddHandlers(s *Services) {
	http.HandleFunc("/owid/register", HandlerRegister(s))
	for i := owidVersion1; i <= owidVersion2; i++ {
		b := fmt.Sprintf("/owid/api/v%d/", i)
		http.HandleFunc(b+"public-key", HandlerPublicKey(s))
		http.HandleFunc(b+"creator", HandlerCreator(s))
		http.HandleFunc(b+"verify", HandlerVerify(s))
	}
}

func returnAPIError(
	s *Services,
	w http.ResponseWriter,
	err error,
	code int) {
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, err.Error(), code)
	if s.config.Debug {
		println(err.Error())
	}
}

func returnServerError(s *Services, w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-cache")
	if s.config.Debug {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		http.Error(w, "", http.StatusInternalServerError)
	}
	if s.config.Debug {
		println(err.Error())
	}
}

func getCreatorFromRequest(s *Services, r *http.Request) (*Creator, error) {

	// Get the node associated with the request.
	c, err := s.store.GetCreator(r.Host)
	if err != nil {
		return nil, err
	}

	return c, nil
}
