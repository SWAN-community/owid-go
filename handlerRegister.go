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
	"net/url"

	"github.com/SWAN-community/common-go"
)

// HandlerRegister handles registering of a domain as a signer.
func HandlerRegister(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// The data model used with the registration template.
		m := Register{
			Services:          s,
			Domain:            r.Host,
			MinNameLength:     minNameLength,
			MaxNameLength:     maxNameLength,
			MaxTermsURLLength: maxTermsURLLength}

		// Check that the domain has not already been registered.
		g, err := s.store.GetSigner(r.Host)
		if err != nil {
			// Problem getting the signer for the host.
			common.ReturnServerError(w, err)
			return
		}
		if g != nil {
			// The host is already registered. It can't be registered again
			// so return an application error.
			common.ReturnApplicationError(w, &common.HttpError{
				Message: fmt.Sprintf("Domain '%s' already registered", g.Domain),
				Code:    http.StatusNotFound})
			return
		}

		// Get any values from the form.
		err = r.ParseForm()
		if err != nil {
			common.ReturnServerError(w, err)
			return
		}

		// Get the OWID signer legal name.
		m.Name = r.Form.Get("name")
		if len(m.Name) <= minNameLength || len(m.Name) > maxNameLength {
			m.NameError = nameLengthMessage
		}

		// Get the OWID signer terms URL.
		if len(r.Form.Get("termsURL")) > maxTermsURLLength {
			m.TermsURLError = termsLengthMessage
		} else {
			u, err := url.ParseRequestURI(r.Form.Get("termsURL"))
			if err != nil {
				m.TermsURLError = termsInvalidMessage
			} else {
				m.TermsURL = u.String()
			}
		}

		// If the form values are valid then store the new signer.
		if m.NameError == "" && m.TermsURLError == "" {
			err := registerNewSigner(s, &m)
			if err != nil {
				// The data passed validation but could not be stored due to
				// an error within the server. Response with some information
				// to indicate to the operator what has happened. This is
				// possible in the register handler because users will never
				// access it. It is only ever called when the signer domain is
				// being setup.
				common.ReturnApplicationError(w, &common.HttpError{
					Request: r,
					Log:     true,
					Message: "Error storing new signer. " +
						"Verify server and storage configuration and restart.",
					Error: err,
					Code:  http.StatusInternalServerError})
			}
		}

		// Return the HTML page using the template to work out how to present
		// the result as either a newly added signer, a request for new signer
		// information, or validation results.
		common.SendHTMLTemplate(w, registerTemplate, &m)
	}
}

func registerNewSigner(s *Services, d *Register) error {

	// Create the new signer with the registration information provided.
	k, err := newKeys()
	if err != nil {
		return err
	}
	g, err := newSigner(d.Domain, d.Name, d.TermsURL, k)
	if err != nil {
		return err
	}

	// Store the signer and if successful mark the registration process as
	// complete.
	err = s.store.addSigner(g)
	if err != nil {
		return err
	} else {
		d.ReadOnly = true
	}

	return nil
}
