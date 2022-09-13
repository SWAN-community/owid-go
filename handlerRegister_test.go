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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SWAN-community/common-go"
)

// TestRegisterHandler uses the HTTP handler to add a new domain to the OWID
// store and verifies that the response is expected and that the store has been
// updated to contain the new information.
func TestRegisterHandler(t *testing.T) {
	t.Run("good", func(t *testing.T) {
		d := time.Now()
		s, rr := testRegisterGetResponse(t, "GET", testDomain, testName,
			testTermsUrl)
		testRegisterOK(t, s, rr, testDomain, testName, testTermsUrl, d)
	})
	t.Run("terms too long", func(t *testing.T) {
		testRegisterValidation(t, "GET", testDomain, testName,
			strings.Repeat("#", maxTermsURLLength+1),
			termsLengthMessage)
	})
	t.Run("terms invalid", func(t *testing.T) {
		testRegisterValidation(t, "GET", testDomain, testName,
			"bad",
			termsInvalidMessage)
	})
}

func testRegisterOK(
	t *testing.T,
	s *Services,
	rr *httptest.ResponseRecorder,
	domain string,
	name string,
	termsUrl string,
	minCreatedDate time.Time) {

	// Check the HTTP status code in the response.
	if rr.Code != http.StatusOK {
		t.Fatal("status invalid")
	}

	// Decompress the response and get the string.
	v := common.ResponseAsStringTest(t, rr)
	if v == "" || strings.Contains(v, "html") == false {
		t.Fatal("handler didn't return HTML")
	}

	// Check that the register domain now exists in the store.
	g, err := s.store.GetSigner(domain)
	if err != nil {
		t.Fatalf("get failed with '%s'", err)
	}
	if g == nil {
		t.Fatal("signer was not registered")
	}
	if g.Domain != domain {
		t.Fatalf("expected domain '%s', found '%s'", domain, g.Domain)
	}
	if name != g.Name {
		t.Fatalf("expected name '%s', found '%s'", name, g.Name)
	}
	if termsUrl != g.TermsURL {
		t.Fatalf("expected terms URL '%s', found '%s'", termsUrl, g.TermsURL)
	}
	if len(g.Keys) != 1 {
		t.Fatal("expected one pair of keys")
	}
	for _, k := range g.Keys {
		if k.PrivateKey == "" {
			t.Fatal("no private key")
		}
		if k.PublicKey == "" {
			t.Fatal("no public key")
		}
		if k.Created.Before(minCreatedDate) {
			t.Fatalf(
				"expected created '%v', found '%v'",
				minCreatedDate,
				k.Created)
		}
	}
}

func testRegisterValidation(
	t *testing.T,
	method string,
	domain string,
	name string,
	termsUrl string,
	message string) {
	_, rr := testRegisterGetResponse(t, method, domain, name, termsUrl)
	testRegisterCheckContent(t, rr, message)
}

func testRegisterGetResponse(
	t *testing.T,
	method string,
	domain string,
	name string,
	termsUrl string) (*Services, *httptest.ResponseRecorder) {

	// Get the services for the test without any signers already added.
	s := getServicesEmpty(t)

	// Send the new name to the domain.
	return s, RegisterTestSignerResponse(t, s, domain, method, name, termsUrl)
}

func testRegisterCheckContent(
	t *testing.T,
	rr *httptest.ResponseRecorder,
	content string) {

	// Decompress the response and get the string.
	v := common.ResponseAsStringTest(t, rr)
	if v == "" || strings.Contains(v, "html") == false {
		t.Fatal("handler didn't return HTML")
	}

	if strings.Contains(v, content) == false {
		t.Fatalf("response HTML did not contain '%s'", content)
	}
}
