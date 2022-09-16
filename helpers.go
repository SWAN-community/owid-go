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
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/SWAN-community/common-go"
)

var testDate = time.Date(2020, time.Month(11), 12, 0, 0, 0, 0, time.UTC)

const (
	testDomain   = "swan.community"
	testName     = "Secure Web Addressability Network"
	testTermsUrl = "https://swan.community"
)

// NewTestSigner creates a new default test signer. A public test method so that
// consuming packages can easilly create test signers to verify their OWID
// target structures.
func NewTestDefaultSigner(t *testing.T) *Signer {
	return NewTestSigner(t, testDomain, testName, testTermsUrl)
}

// NewTestSigner creates a new test signer for the domain, name, and terms
// provided. A public test method so that consuming packages can easilly create
// test signers to verify their OWID target structures.
func NewTestSigner(
	t *testing.T,
	domain string,
	name string,
	termsURL string) *Signer {
	c, err := NewCrypto()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := c.privateKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := c.publicKeyToPemString()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSigner(
		domain,
		name,
		termsURL,
		&Keys{PublicKey: publicKey, PrivateKey: privateKey, Created: testDate})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// RegisterTestSignerAndKeys calls the register handler to add a new signer to
// the services provided. Used to setup tests that depend on the OWID pacakge.
func RegisterTestSigner(
	t *testing.T,
	s *Services,
	domain string,
	method string,
	name string,
	termsUrl string) {
	rr := RegisterTestSignerResponse(t, s, domain, method, name, termsUrl)
	if rr.Code != http.StatusOK {
		t.Fatalf("code '%d' registering '%s'", rr.Code, domain)
	}
}

// AddKeysTest calls the add keys handler to add new keys for the signer
// associated with the domain using the services provided. Used to setup tests
// that depend on the OWID pacakge.
func AddKeysTest(
	t *testing.T,
	s *Services,
	domain string,
	method string,
	accessKey string) {
	rr := AddKeysTestResponse(t, s, domain, method, accessKey)
	if rr.Code != http.StatusOK {
		t.Fatalf("code '%d' adding keys for '%s'", rr.Code, domain)
	}
}

func RegisterTestSignerResponse(
	t *testing.T,
	s *Services,
	domain string,
	method string,
	name string,
	termsUrl string) *httptest.ResponseRecorder {
	u, err := url.Parse(fmt.Sprintf(
		"%s://%s/owid/api/v1/register",
		s.config.Scheme,
		testDomain))
	q := &url.Values{}
	q.Set("name", name)
	q.Set("termsURL", termsUrl)
	u.RawQuery = q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return common.HTTPTest(
		t,
		method,
		u,
		nil,
		HandlerRegister(s))
}

func AddKeysTestResponse(
	t *testing.T,
	s *Services,
	domain string,
	method string,
	accessKey string) *httptest.ResponseRecorder {
	u, err := url.Parse(fmt.Sprintf(
		"%s://%s/owid/api/v1/register?accessKey=%s",
		s.config.Scheme,
		domain,
		accessKey))
	if err != nil {
		t.Fatal(err)
	}
	return common.HTTPTest(
		t,
		method,
		u,
		nil,
		HandlerAddKeys(s))
}

func StoreNewTestSigner(
	t *testing.T,
	store Store,
	domain string,
	name string,
	termsUrl string) {
	n := NewTestSigner(t, testDomain, testName, testTermsUrl)
	err := store.addSigner(n)
	if err != nil {
		t.Fatal(err)
	}
	err = store.refresh()
	if err != nil {
		t.Fatal(err)
	}
	g, err := store.GetSigner(testDomain)
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.CreateOWIDandSign(&ByteArray{Data: []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.Verify(b)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("verification should pass")
	}
}
