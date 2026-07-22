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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	registerDomain      = testDomain + " register"
	registerName        = testOrgName + "register"
	registerContractURL = "https://test.com/" + testOrgName
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
	if len(d) != 4 {
		t.Errorf("too many keys returned")
		return
	}
}

// TestPublicKeyHandlerSPKI verifies that the public key endpoint returns the
// PEM encoded key in SPKI format.
func TestPublicKeyHandlerSPKI(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("format", "spki")
	rr := send(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		q)
	v := decompressAsString(t, rr)
	if strings.HasPrefix(v, "-----BEGIN PUBLIC KEY-----") == false {
		t.Error("handler did not return a PEM public key")
		return
	}
	spki, err := c.SubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	if v != spki {
		t.Error("returned key does not match the creator SPKI key")
	}
}

// TestPublicKeyHandlerPKCS verifies that the public key endpoint returns the
// PEM encoded key in PKCS format.
func TestPublicKeyHandlerPKCS(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("format", "pkcs")
	rr := send(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		q)
	v := decompressAsString(t, rr)
	if strings.HasPrefix(v, "-----BEGIN PUBLIC KEY-----") == false {
		t.Error("handler did not return a PEM public key")
		return
	}
	if v != c.publicKey {
		t.Error("returned key does not match the creator public key")
	}
}

// TestPublicKeyHandlerInvalidFormat verifies that the public key endpoint
// rejects an unknown format parameter. The current implementation returns
// status 500 rather than 400 for a bad format value. This test documents
// that behavior.
func TestPublicKeyHandlerInvalidFormat(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("format", "invalid")
	rr := sendRaw(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		q)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf(
			"handler returned wrong status code: got %v want %v",
			rr.Code,
			http.StatusInternalServerError)
	}
}

// TestPublicKeyHandlerWithDateSelectsKey verifies that a date selects the key
// that was current then via a configured dated key store.
func TestPublicKeyHandlerWithDateSelectsKey(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetPublicKeyStore(NewDatedPublicKeyStore(map[string][]DatedKey{
		testDomain: {
			{Created: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "KEY-OLD"},
			{Created: time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), PublicKey: "KEY-NEW"},
		},
	}))
	minutes := uint32(
		time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC).Sub(ioDateBase).Minutes())
	q := url.Values{}
	q.Set("format", "pkcs")
	q.Set("date", strconv.FormatUint(uint64(minutes), 10))
	rr := send(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	if v := decompressAsString(t, rr); v != "KEY-OLD" {
		t.Errorf("got %q, want KEY-OLD", v)
	}
}

// TestPublicKeyHandlerDateBeforeOldestReturns404 verifies that a date before
// any known key returns 404.
func TestPublicKeyHandlerDateBeforeOldestReturns404(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetPublicKeyStore(NewDatedPublicKeyStore(map[string][]DatedKey{
		testDomain: {
			{Created: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "KEY"},
		},
	}))
	q := url.Values{}
	q.Set("format", "pkcs")
	q.Set("date", "1440") // 2020-01-02, before the only key
	rr := sendRaw(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	if rr.Code != http.StatusNotFound {
		t.Errorf("got %v, want %v", rr.Code, http.StatusNotFound)
	}
}

// TestPublicKeyHandlerMalformedDateReturns400 verifies that a non-numeric date
// returns 400.
func TestPublicKeyHandlerMalformedDateReturns400(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Set("format", "pkcs")
	q.Set("date", "notanumber")
	rr := sendRaw(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("got %v, want %v", rr.Code, http.StatusBadRequest)
	}
}

// TestVerifyHandlerValid verifies that the verify endpoint returns valid
// true for an OWID signed by the creator for the host domain.
func TestVerifyHandlerValid(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	if verifyResponse(t, s, a) != true {
		t.Error("valid OWID should return valid true")
	}
}

// TestVerifyHandlerTampered verifies that the verify endpoint returns valid
// false for an OWID with a modified payload byte.
func TestVerifyHandlerTampered(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}

	// Modify the last byte of the payload which is immediately before the
	// signature.
	a[len(a)-signatureLength-1] = a[len(a)-signatureLength-1] + 1
	if verifyResponse(t, s, base64.StdEncoding.EncodeToString(a)) != false {
		t.Error("tampered OWID should return valid false")
	}
}

// verifyResponse sends the base 64 OWID to the verify handler and returns
// the valid field of the JSON response.
func verifyResponse(t *testing.T, s *Services, a string) bool {
	q := url.Values{}
	q.Set("owid", a)
	rr := send(
		t,
		HandlerVerify(s),
		testDomain,
		"/owid/api/v3/verify",
		q)
	var v verify
	err := json.Unmarshal([]byte(decompressAsString(t, rr)), &v)
	if err != nil {
		t.Fatal(err)
	}
	return v.Valid
}

func send(
	t *testing.T,
	f http.HandlerFunc,
	d string,
	p string,
	q url.Values) *httptest.ResponseRecorder {
	rr := sendRaw(t, f, d, p, q)
	if rr == nil {
		return nil
	}

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
		return nil
	}
	return rr
}

// sendRaw calls the handler and returns the response without checking the
// status code. Used by tests that expect a failure status.
func sendRaw(
	t *testing.T,
	f http.HandlerFunc,
	d string,
	p string,
	q url.Values) *httptest.ResponseRecorder {

	// Create the HTTP request and set the parameters.
	req, err := http.NewRequest("GET", p, nil)
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
	c := NewConfig("appsettings.test.none.json")
	a := NewAccessSimple([]string{"key1", "key2"})
	ts := newTestStore()
	ts.addCreator(testDomain, testOrgName, registerContractURL)
	return NewServices(c, ts, a), nil
}

// TestPublicKeyHandlerAuthorizerDenies verifies that a configured authorizer
// can reject a public key request with a 401.
func TestPublicKeyHandlerAuthorizerDenies(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(func(r *http.Request) error {
		return fmt.Errorf("a subscription credential is required")
	})
	q := url.Values{}
	q.Set("format", "spki")
	rr := sendRaw(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		q)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf(
			"handler returned wrong status code: got %v want %v",
			rr.Code,
			http.StatusUnauthorized)
	}
	if strings.Contains(
		rr.Body.String(),
		"a subscription credential is required") == false {
		t.Error("response body should contain the authorizer error text")
	}
}

// TestCreatorHandlerAuthorizerDenies verifies that a configured authorizer
// can reject a creator request with a 401.
func TestCreatorHandlerAuthorizerDenies(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(func(r *http.Request) error {
		return fmt.Errorf("a subscription credential is required")
	})
	rr := sendRaw(
		t,
		HandlerCreator(s),
		testDomain,
		"/owid/api/v3/creator",
		url.Values{})
	if rr.Code != http.StatusUnauthorized {
		t.Errorf(
			"handler returned wrong status code: got %v want %v",
			rr.Code,
			http.StatusUnauthorized)
	}
	if strings.Contains(
		rr.Body.String(),
		"a subscription credential is required") == false {
		t.Error("response body should contain the authorizer error text")
	}
}

// TestPublicKeyHandlerAuthorizerAllows verifies that an authorizer returning
// nil lets the request through.
func TestPublicKeyHandlerAuthorizerAllows(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(func(r *http.Request) error {
		return nil
	})
	q := url.Values{}
	q.Set("format", "spki")
	rr := send(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		q)
	v := decompressAsString(t, rr)
	if strings.HasPrefix(v, "-----BEGIN PUBLIC KEY-----") == false {
		t.Error("handler did not return a PEM public key")
	}
}

// TestCreatorHandlerAuthorizerAllows verifies that an authorizer returning
// nil lets the creator request through.
func TestCreatorHandlerAuthorizerAllows(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(func(r *http.Request) error {
		return nil
	})
	rr := send(
		t,
		HandlerCreator(s),
		testDomain,
		"/owid/api/v3/creator",
		url.Values{})
	d := decompressAsMap(t, rr)
	if d["domain"] != testDomain {
		t.Errorf(
			"expected domain '%s', returned '%s'",
			testDomain,
			d["domain"])
	}
}

// TestVerifyHandlerIgnoresAuthorizer verifies that the verify end point stays
// open when a denying authorizer is configured.
func TestVerifyHandlerIgnoresAuthorizer(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	s.SetAuthorizer(func(r *http.Request) error {
		return fmt.Errorf("a subscription credential is required")
	})
	if verifyResponse(t, s, a) != true {
		t.Error("verify should not require a credential")
	}
}

// TestVerifyClientSendsDate verifies that the client Verify method forwards
// the OWID's own date to the public-key endpoint, so a creator that rotates
// keys can return the key that was current when the OWID was signed.
func TestVerifyClientSendsDate(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte(testPayload))
	if err != nil {
		t.Fatal(err)
	}

	var gotDate string
	handler := HandlerPublicKey(s)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotDate = r.URL.Query().Get("date")
			// The default key store is keyed by host, so present the request
			// as if it arrived at the creator domain.
			r.Host = testDomain
			handler(w, r)
		}))
	defer srv.Close()

	// Route the package HTTP client to the test server while leaving the
	// OWID's real domain intact, since the signature covers the domain.
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	orig := client
	defer func() { client = orig }()
	client = &http.Client{Transport: &redirectTransport{target: target}}

	valid, err := o.Verify("https")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("client verify against the dated endpoint should succeed")
	}
	want := strconv.FormatUint(
		uint64(o.Date.Sub(ioDateBase).Minutes()), 10)
	if gotDate != want {
		t.Errorf("client sent date %q, want %q", gotDate, want)
	}
}

// redirectTransport sends every request to a fixed target host, used to point
// the client at a test server without altering the request URL's original
// host that the OWID signature depends on.
type redirectTransport struct {
	target *url.URL
}

func (rt *redirectTransport) RoundTrip(
	r *http.Request) (*http.Response, error) {
	r.URL.Scheme = rt.target.Scheme
	r.URL.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(r)
}
