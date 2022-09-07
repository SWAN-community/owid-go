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
	"fmt"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/SWAN-community/access-go"
)

// Test access key used with the fixed access service for testing.
const testAccessKey = "A"

func decompressAsMap(
	t *testing.T,
	rr *httptest.ResponseRecorder) map[string]interface{} {
	var d map[string]interface{}
	br, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatal(fmt.Errorf("error decompressing: %w", err))
	}
	b, _ := io.ReadAll(br)
	err = json.Unmarshal(b, &d)
	if err != nil {
		t.Fatal(fmt.Errorf("error unmarshalling: %w", err))
	}
	return d
}

func decompressAsString(
	t *testing.T,
	rr *httptest.ResponseRecorder) string {
	br, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatal(fmt.Errorf("error decompressing: %w", err))
	}
	b, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func getServicesWithDefault(t *testing.T) *Services {
	s := getServicesEmpty(t)
	s.store.addSigner(NewTestSigner(t, testDomain, testName, testTermsUrl))
	return s
}

func getServicesEmpty(t *testing.T) *Services {
	c := NewConfig("appsettings.test.none.json")
	return NewServices(
		&c,
		newTestStore(),
		access.NewFixed([]string{testAccessKey}))
}
