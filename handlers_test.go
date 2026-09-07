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

// testContractURL is the contract URL the test creators are given.
const testContractURL = "https://test.com/" + testOrgName

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
	v := publicKeyAnswer(t, rr)
	if strings.HasPrefix(v.PublicKey, "-----BEGIN PUBLIC KEY-----") == false {
		t.Error("handler did not return a PEM public key")
		return
	}
	spki, err := c.SubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	if v.PublicKey != spki {
		t.Error("returned key does not match the creator SPKI key")
	}
	if v.Format != SpkiFormat {
		t.Errorf("the answer should echo the format asked for, got %q", v.Format)
	}
	if v.ValidFrom != nil || v.ValidTo != nil {
		t.Error("a single key with no schedule should be stated with no moments")
	}
}

// TestPublicKeyHandlerDefaultsToSPKI verifies that a request naming no format
// is answered in the one format defined, and that the answer says so.
func TestPublicKeyHandlerDefaultsToSPKI(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.store.GetCreator(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	rr := send(
		t,
		HandlerPublicKey(s),
		testDomain,
		"/owid/api/v3/public-key",
		url.Values{})
	v := publicKeyAnswer(t, rr)
	if v.Format != SpkiFormat {
		t.Errorf("a request naming no format should be answered in spki, got %q", v.Format)
	}
	spki, err := c.SubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	if v.PublicKey != spki {
		t.Error("returned key does not match the creator SPKI key")
	}
}

// TestPublicKeyHandlerRefusesAnotherFormat verifies that the public key end
// point answers 400 to a format it does not serve, pkcs among them, rather
// than answering in an encoding the caller did not ask for.
func TestPublicKeyHandlerRefusesAnotherFormat(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"pkcs", "invalid"} {
		q := url.Values{}
		q.Set("format", format)
		rr := sendRaw(
			t,
			HandlerPublicKey(s),
			testDomain,
			"/owid/api/v3/public-key",
			q)
		if rr.Code != http.StatusBadRequest {
			t.Errorf(
				"format %q should be refused with %v, got %v",
				format,
				http.StatusBadRequest,
				rr.Code)
		}
	}
}

// TestPublicKeyHandlerWithDateSelectsKey verifies that a date selects the key
// that was current then via a configured dated key store.
func TestPublicKeyHandlerWithDateSelectsKey(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := freshPem(t), freshPem(t)
	oldStart := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	newStart := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	s.SetPublicKeyStore(NewDatedPublicKeyStore(map[string][]DatedKey{
		testDomain: {
			{StartsAt: oldStart, PublicKey: oldKey},
			{StartsAt: newStart, PublicKey: newKey},
		},
	}))
	minutes := uint32(
		time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC).Sub(ioDateBase).Minutes())
	q := url.Values{}
	q.Set("format", SpkiFormat)
	q.Set("date", strconv.FormatUint(uint64(minutes), 10))
	rr := send(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	v := publicKeyAnswer(t, rr)
	if v.PublicKey != oldKey {
		t.Errorf("got %q, want the old key", v.PublicKey)
	}
	if v.ValidFrom == nil || !v.ValidFrom.Equal(oldStart) || v.ValidTo == nil || !v.ValidTo.Equal(newStart) {
		t.Errorf("the old key should be stated valid from its start to the new key's start, got %+v", v)
	}
	// The last key of the schedule has no end.
	q.Set("date", strconv.FormatUint(uint64(uint32(
		time.Date(2026, 3, 20, 0, 0, 0, 0, time.UTC).Sub(ioDateBase).Minutes())), 10))
	rr = send(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	v = publicKeyAnswer(t, rr)
	if v.PublicKey != newKey || v.ValidFrom == nil || !v.ValidFrom.Equal(newStart) || v.ValidTo != nil {
		t.Errorf("the last key should be stated valid from its start with no end, got %+v", v)
	}
}

// freshPem is the public key of a newly made key pair, in PEM form.
func freshPem(t *testing.T) string {
	t.Helper()
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.getSubjectPublicKeyInfo()
	if err != nil {
		t.Fatal(err)
	}
	return pem
}

// publicKeyAnswer reads the JSON body of a public key response.
func publicKeyAnswer(t *testing.T, rr *httptest.ResponseRecorder) PublicKeyResponse {
	t.Helper()
	var v PublicKeyResponse
	if err := json.Unmarshal([]byte(decompressAsString(t, rr)), &v); err != nil {
		t.Fatalf("the answer should be the JSON form: %v", err)
	}
	return v
}

// TestPublicKeyHandlerRefusesToAnswerWithAKeyItCannotRead checks that a store
// holding something that is not a public key is reported as a server error
// rather than passed to clients as an answer.
func TestPublicKeyHandlerRefusesToAnswerWithAKeyItCannotRead(t *testing.T) {
	s, err := getServices()
	if err != nil {
		t.Fatal(err)
	}
	s.SetPublicKeyStore(NewDatedPublicKeyStore(map[string][]DatedKey{
		testDomain: {{StartsAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "KEY-OLD"}},
	}))
	q := url.Values{}
	q.Set("format", SpkiFormat)
	rr := sendRaw(t, HandlerPublicKey(s), testDomain, "/owid/api/v3/public-key", q)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("a key that cannot be read should be a server error, got %d", rr.Code)
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
			{StartsAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), PublicKey: "KEY"},
		},
	}))
	q := url.Values{}
	q.Set("format", SpkiFormat)
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
	q.Set("format", SpkiFormat)
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
	ts.addCreator(testDomain, testOrgName, testContractURL)
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
	v := publicKeyAnswer(t, rr)
	if strings.HasPrefix(v.PublicKey, "-----BEGIN PUBLIC KEY-----") == false {
		t.Error("handler did not return a PEM public key")
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
		uint64(o.date.Sub(ioDateBase).Minutes()), 10)
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
