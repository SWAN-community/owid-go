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
