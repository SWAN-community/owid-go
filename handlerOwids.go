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
)

// HandlerNodesJSON is a handler that returns a list of all the alive nodes
// which is then used to serialize to JSON.
func HandlerOwidsJSON(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		j, err := getJSON(s)
		if err != nil {
			returnAPIError(s, w, err, http.StatusInternalServerError)
			return
		}
		sendResponse(s, w, "application/json", j)
	}
}

func getJSON(s *Services) ([]byte, error) {
	j, err := json.Marshal(s.store.GetCreators())
	if err != nil {
		return nil, err
	}
	return j, nil
}
