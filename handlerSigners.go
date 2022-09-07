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

// HandlerSignersAsJSON is a handler that returns a list of all the known
// domains that relate to signers in JSON format.
func HandlerSigners(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := getSignersAsJSON(s)
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}
		common.SendJS(w, j)
	}
}

func getSignersAsJSON(s *Services) ([]byte, error) {
	j, err := json.Marshal(s.store.GetSigners())
	if err != nil {
		return nil, err
	}
	return j, nil
}
