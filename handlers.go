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
	"compress/gzip"
	"fmt"
	"html/template"
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

// getWriter creates a new compressed writer for the content type provided.
func getWriter(w http.ResponseWriter, c string) *gzip.Writer {
	g := gzip.NewWriter(w)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", c)
	w.Header().Set("Cache-Control", "no-cache")
	return g
}

func sendHTMLTemplate(s *Services,
	w http.ResponseWriter,
	t *template.Template,
	m interface{}) {
	g := getWriter(w, "text/html; charset=utf-8")
	defer g.Close()
	err := t.Execute(g, m)
	if err != nil {
		returnServerError(s, w, err)
	}
}

func sendResponse(
	s *Services,
	w http.ResponseWriter,
	c string,
	b []byte) {
	g := getWriter(w, c)
	defer g.Close()
	w.Header().Set("Access-Control-Allow-Origin", "*")
	l, err := g.Write(b)
	if err != nil {
		returnAPIError(s, w, err, http.StatusInternalServerError)
		return
	}
	if l != len(b) {
		returnAPIError(
			s,
			w,
			fmt.Errorf("Byte count mismatch"),
			http.StatusInternalServerError)
		return
	}
}
