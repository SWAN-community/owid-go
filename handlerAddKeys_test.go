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
	"testing"
)

func TestAddKeysHandler(t *testing.T) {
	t.Run("all good", func(t *testing.T) {
		s, rr := testAddKeysGetResponse(t, testDomain, http.MethodGet, testAccessKey)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected '%d' status", http.StatusOK)
		}
		n, err := s.GetSigner(testDomain)
		if err != nil {
			t.Fatal(err)
		}
		if len(n.Keys) != 2 {
			t.Fatal("expected signer to have two keys")
		}
	})
	t.Run("bad access key", func(t *testing.T) {
		_, rr := testAddKeysGetResponse(t, testDomain, http.MethodGet, "B")
		if rr.Code != http.StatusNetworkAuthenticationRequired {
			t.Fatalf("expected '%d' status",
				http.StatusNetworkAuthenticationRequired)
		}
	})
	t.Run("bad domain", func(t *testing.T) {
		_, rr := testAddKeysGetResponse(t, "not.exist", http.MethodGet, testAccessKey)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected '%d' status", http.StatusBadRequest)
		}
	})
}

func testAddKeysGetResponse(
	t *testing.T,
	domain string,
	method string,
	accessKey string) (*Services, *httptest.ResponseRecorder) {

	// Get the services for the test without any signers already added.
	s := getServicesWithDefault(t)

	// Send the new name to the domain.
	return s, AddKeysTestResponse(t, s, domain, method, accessKey)
}
