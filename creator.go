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

// Creator of Open Web Ids and immutable data.
type Creator struct {
	domain     string // The registered domain name and key fields
	privateKey string
	publicKey  string
	name       string // The name of the entity associated with the domain
}

// Domain associated with the creator.
func (c *Creator) Domain() string { return c.domain }

// CreateOWID makes a new OWID for the payload provided.
func (c *Creator) CreateOWID(payload string) (string, error) {

	date := time.Now().UTC()

	// Get signing key
	cry, err := NewCryptoSignOnly(c.privateKey)
	if err != nil {
		return "", err
	}

	// Generate signature of OWID
	signature, err := cry.Sign(date, []byte(payload))
	if err != nil {
		return "", err
	}

	// Create the OWID
	o, err := NewOwid(c.domain, signature, date, []byte(payload))
	if err != nil {
		return "", err
	}

	// Get the OWID as a base64 string
	return o.EncodeAsBase64()
}

func newCreator(
	domain string,
	privateKey string,
	publicKey string,
	name string) (*Creator, error) {
	c := Creator{
		domain,
		privateKey,
		publicKey,
		name}
	return &c, nil
}
