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

import "time"

const (
	testDomain  = "51degrees.com"
	testOrgName = "51degrees"
	testPayload = "test"
)

var testDate = time.Date(2020, time.Month(11), 12, 0, 0, 0, 0, time.UTC)

type testStore struct {
	common
}

// newTestStore creates a new test store and adds the domain 51degrees.com
// as an OWID creator.
func newTestStore() *testStore {
	var ts testStore
	ts.init()
	return &ts
}

func (ts *testStore) GetCreator(domain string) (*Creator, error) {
	return ts.creators[domain], nil
}

func (ts *testStore) setCreator(c *Creator) error {
	ts.creators[c.domain] = c
	return nil
}

func newTestCreator(
	domain string,
	name string,
	contractURL string) (*Creator, error) {
	cry, err := NewCrypto()
	if err != nil {
		return nil, err
	}
	privateKey, err := cry.privateKeyToPemString()
	if err != nil {
		return nil, err
	}
	publicKey, err := cry.publicKeyToPemString()
	if err != nil {
		return nil, err
	}
	c := newCreator(
		domain,
		privateKey,
		publicKey,
		name,
		contractURL)
	return c, nil
}

func (ts *testStore) addCreator(
	domain string,
	name string,
	contractURL string) error {
	c, err := newTestCreator(domain, name, contractURL)
	if err != nil {
		return err
	}
	ts.setCreator(c)
	return nil
}
