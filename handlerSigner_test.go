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
	"testing"

	"github.com/SWAN-community/common-go"
)

// TestSignerHandler verifies that the handler returns the expected results by
// comparing the data in the store to that returned form the handler.
func TestSignerHandler(t *testing.T) {

	// Get the services with the default signer added.
	s := getServicesWithDefault(t)

	// Check the expected creator is present in the store.
	expected, err := s.store.GetSigner(testDomain)
	if err != nil {
		t.Fatalf("creator '%s' not in store", testDomain)
	}

	// Create the HTTP request for the test domain and run the handler.
	rr := common.HTTPTest(
		t,
		"GET",
		testDomain,
		"/owid/api/v1/signer",
		nil,
		HandlerSigner(s))

	// Verify the status code.
	if rr.Code != http.StatusOK {
		t.Fatalf(
			"expected code '%d', returned '%d'",
			http.StatusOK,
			rr.Code)
	}

	// Decompress the response and turn it into JSON map.
	d := decompressAsMap(t, rr)

	if d == nil {
		t.Fatal("no response returned")
	}

	// Check the values of the expected fields are present.
	if expected.Domain != d["domain"] {
		t.Fatalf(
			"expected domain '%s', returned '%s'",
			expected.Domain,
			d["domain"])
	}
	if expected.Name != d["name"] {
		t.Fatalf(
			"expected name '%s', returned '%s'",
			expected.Name,
			d["name"])
	}

	// Check no additional information has been returned.
	if len(d) != 4 {
		t.Fatal("too many keys returned")
	}
}
