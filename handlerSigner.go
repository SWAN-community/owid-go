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

	"github.com/SWAN-community/common-go"
)

// HandlerSigner Returns the public information associated with the creator.
func HandlerSigner(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		g := s.GetSignerHttp(w, r)
		if g == nil {
			return
		}
		err := r.ParseForm()
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		ps, err := publicSigner(g)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		u, err := json.Marshal(ps)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "max-age=60")
		common.SendJS(w, u)
	}
}

func publicSigner(s *Signer) (*SignerPublic, error) {
	var err error
	ps := &SignerPublic{
		Domain:   s.Domain,
		Name:     s.Name,
		TermsURL: s.TermsURL}
	ps.PublicKeys, err = s.PublicKeys()
	if err != nil {
		return nil, err
	}
	return ps, nil
}
