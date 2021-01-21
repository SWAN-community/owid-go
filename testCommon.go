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
	testDomain    = "51degrees.com"
	testOrgName   = "51degrees"
	testPayload   = "test"
	testPublicKey = `
-----BEGIN RSA PUBLIC KEY-----
MEgCQQCvRGWAZSb9mwygC+sptzSzm+apd9jKE2SNMZQEXQBe9HFT2S0iAdjKUGUr
tUoaQi6si70CTvqTGX+1aZ1yyYwJAgMBAAE=
-----END RSA PUBLIC KEY-----`
	testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAK9EZYBlJv2bDKAL6ym3NLOb5ql32MoTZI0xlARdAF70cVPZLSIB
2MpQZSu1ShpCLqyLvQJO+pMZf7VpnXLJjAkCAwEAAQJATGfKv/BY0RH4rQTFHchq
Rypdod9HOMC/gvXsCwLoGHxKkocKz2svKnhxbJrw6nkLAc2TZvqpUAH5mjPhrG/H
oQIhAOMDilx88RjVP0ZmGWmXSCwNyOLM+jufcCB6vaXysfjNAiEAxaVmVUqHc95G
ZmRwQwct7oX0Ef240EZ6/wc5uOHEEC0CIQCn4axm7XcXGEzs8QCGF/ylp6QSJehA
Q46WVm791FdNWQIhAK3P8RicvFYXaU3ukhNAIxKaVrPjrz3qXYwdrJN8Z9HZAiEA
vj5eQIKZ1CG7XqIuNWc7obEfTjeWkYBqrNteyekbF+o=
-----END RSA PRIVATE KEY-----`
	testSignature   = "XAd5GNk53Ww/qm8KkS6Z8/OLOFxJoDrZrIwKMj4yPUOEUCr2u2EqhG9APuVWqzhj8OQ1B5zLcX9aJWfXk9xqng==="
	testOwid        = "NTFkZWdyZWVzLmNvbQABY3F2b21VRUE3WUtnSStOWGdIU1c2cXhyQkd5SERQN1dLbVc1Rjc1U3BYd21pd3g0MGpoeVNteDZWSFJJNGYyRjRHMW5xbXNLbElKSjFIdXB2cjdKL1E9PQABPAQAAAB0ZXN0"
	testJSON        = `{"domain":"51degrees.com","version":1,"signature":"cqvomUEA7YKgI+NXgHSW6qxrBGyHDP7WKmW5F75SpXwmiwx40jhySmx6VHRI4f2F4G1nqmsKlIJJ1Hupvr7J/Q==","date":"2020-11-12T00:00:00Z","payload":"dGVzdA=="}`
	testValidJSON   = `{"domain":"51degrees.com","version":1,"signature":"cqvomUEA7YKgI+NXgHSW6qxrBGyHDP7WKmW5F75SpXwmiwx40jhySmx6VHRI4f2F4G1nqmsKlIJJ1Hupvr7J/Q==","date":"2020-11-12T00:00:00Z","payload":"dGVzdA==","name":"51degrees","valid":true}`
	testCreatorJSON = `{"domain":"51degrees.com","name":"51degrees","public-key":"\n-----BEGIN RSA PUBLIC KEY-----\nMEgCQQCvRGWAZSb9mwygC+sptzSzm+apd9jKE2SNMZQEXQBe9HFT2S0iAdjKUGUr\ntUoaQi6si70CTvqTGX+1aZ1yyYwJAgMBAAE=\n-----END RSA PUBLIC KEY-----"}`
)

var testDate = time.Date(2020, time.Month(11), 12, 0, 0, 0, 0, time.UTC)

type testStore struct {
	common
}

func newTestStore() (*testStore, error) {
	var ts testStore
	return &ts, nil
}

func (ts *testStore) GetCreator(domain string) (*Creator, error) {
	var c Creator
	c.domain = domain
	c.name = testOrgName
	c.privateKey = testPrivateKey
	c.publicKey = testPublicKey
	return &c, nil
}

func (ts *testStore) setCreator(c *Creator) error {
	return nil
}

func getNewOWID(s Store) (*OWID, error) {
	c, err := s.GetCreator(testDomain)
	if err != nil {
		return nil, err
	}
	cry, err := NewCryptoSignOnly(c.privateKey)
	if err != nil {
		return nil, err
	}
	o, err := NewOwid(testDomain, time.Now().UTC(), []byte(testPayload))
	if err != nil {
		return nil, err
	}
	err = o.Sign(cry, nil)
	if err != nil {
		return nil, err
	}
	return o, nil
}
