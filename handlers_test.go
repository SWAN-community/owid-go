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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	registerDomain = testDomain + " register"
	registerName   = testOrgName + "register"
)

// TestRegisterHandler uses the HTTP handler to add a new domain to the OWID
// store and verifies that the response is expected and that the store has been
// updated to contain the new information.
func TestRegisterHandler(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}

	// Send the new name to the domain.
	data := url.Values{}
	data.Set("name", registerName)
	rr := send(
		t,
		HandlerRegister(s),
		registerDomain,
		"/owid/api/v1/register",
		data)

	// Decompress the response and turn it into JSON map.
	v := decompressAsString(t, rr)
	if v == "" || strings.Contains(v, "html") == false {
		t.Error("handler didn't return HTML")
		return
	}

	// Check that the register domain now exists in the store.
	c, err := s.store.GetCreator(registerDomain)
	if err != nil {
		t.Errorf("get failed with '%s'", err)
		return
	}
	if registerDomain != c.domain {
		t.Errorf("expected domain '%s', found '%s'", registerDomain, c.domain)
		return
	}
	if registerDomain != c.domain {
		t.Errorf("expected name '%s', found '%s'", registerName, c.name)
		return
	}
	if c.privateKey == "" {
		t.Error("no private key")
		return
	}
	if c.publicKey == "" {
		t.Error("no public key")
		return
	}
}

// TestCreatorHandler verifies that the handler returns the expected results
// by comparing the data in the store to that returned form the handler.
func TestCreatorHandler(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}

	// Check the expected creator is present in the store.
	expected, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Errorf("creator '%s' not in store", testDomain)
		return
	}

	// Create the HTTP request and set the parameters.
	rr := send(
		t,
		HandlerCreator(s),
		testDomain,
		"/owid/api/v1/creator",
		url.Values{})

	// Decompress the response and turn it into JSON map.
	d := decompressAsMap(t, rr)

	// Check the values of the expected fields are present.
	if expected.domain != d["domain"] {
		t.Errorf(
			"expected domain '%s', returned '%s'",
			expected.domain,
			d["domain"])
		return
	}
	if expected.name != d["name"] {
		t.Errorf(
			"expected name '%s', returned '%s'",
			expected.name,
			d["name"])
		return
	}
	spki, _ := expected.SubjectPublicKeyInfo()
	if spki != d["publicKeySPKI"] {
		t.Errorf(
			"expected SPKI public key '%s', returned '%s'",
			spki,
			d["publicKeySPKI"])
		return
	}

	// Check no additional information has been returned.
	if len(d) != 3 {
		t.Errorf("too many keys returned")
		return
	}
}

func send(
	t *testing.T,
	f http.HandlerFunc,
	d string,
	p string,
	q url.Values) *httptest.ResponseRecorder {

	// Create the HTTP request and set the parameters.
	req, err := http.NewRequest("GET", "/owid/api/v1/creator", nil)
	if err != nil {
		t.Error("could not create new request")
		return nil
	}
	req.Host = d

	// Add the access key for verification.
	q.Set("accessKey", "key1")
	req.URL.RawQuery = q.Encode()

	// Call the handler function.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(f)
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
		return nil
	}
	return rr
}

func decompressAsMap(
	t *testing.T,
	rr *httptest.ResponseRecorder) map[string]string {
	var d map[string]string
	br, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Errorf("error '%s' decompressing", err)
		return nil
	}
	b, _ := io.ReadAll(br)
	err = json.Unmarshal(b, &d)
	if err != nil {
		t.Errorf("error '%s' unmarshalling response to json", err)
		return nil
	}
	return d
}

func decompressAsString(
	t *testing.T,
	rr *httptest.ResponseRecorder) string {
	br, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Errorf("error '%s' decompressing", err)
		return ""
	}
	b, _ := io.ReadAll(br)
	return string(b)
}
func getServices() (*Services, error) {
	c := NewConfig("appsettings.Test.json")
	a := NewAccessSimple([]string{"key1", "key2"})
	ts := newTestStore()
	ts.addCreator(testDomain, testOrgName)
	return NewServices(c, ts, a), nil
}
