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
	"time"
)

// Creator of Open Web Ids and immutable data.
type Creator struct {
	domain     string // The registered domain name and key fields
	privateKey string
	publicKey  string
	name       string // The name of the entity associated with the domain
	sign       *Crypto
	verify     *Crypto
}

// CreateOWID returns a new unsigned OWID from the creator containing the
// payload provided.
func (c *Creator) CreateOWID(payload []byte) *OWID {
	var o OWID
	o.Version = owidVersion
	o.Domain = c.domain
	o.Date = time.Now()
	o.Payload = payload
	return &o
}

// Sign the OWID by updating the signature field.
func (c *Creator) Sign(o *OWID, others ...*OWID) error {
	if c.domain != o.Domain {
		return fmt.Errorf(
			"Can't use creator '%s' to sign OWID for domain '%s'",
			c.domain,
			o.Domain)
	}
	x, err := c.NewCryptoSignOnly()
	if err != nil {
		return err
	}
	return o.Sign(x, others)
}

// Verify the OWID and any other OWIDs are valid for this creator.
func (c *Creator) Verify(o *OWID, others ...*OWID) (bool, error) {
	if c.domain != o.Domain {
		return false, fmt.Errorf(
			"Can't use creator '%s' to verify OWID for domain '%s'",
			c.domain,
			o.Domain)
	}
	x, err := c.NewCryptoVerifyOnly()
	if err != nil {
		return false, err
	}
	return o.VerifyWithCrypto(x, others)
}

// NewCryptoSignOnly creates a new instance of the Crypto structure
// for signing OWIDs only.
func (c *Creator) NewCryptoSignOnly() (*Crypto, error) {
	if c.sign == nil {
		var err error
		c.sign, err = NewCryptoSignOnly(c.privateKey)
		if err != nil {
			return nil, err
		}
	}
	return c.sign, nil
}

// NewCryptoVerifyOnly creates a new instance of the Crypto structure
// for Verifying OWIDs only.
func (c *Creator) NewCryptoVerifyOnly() (*Crypto, error) {
	if c.verify == nil {
		var err error
		c.verify, err = NewCryptoVerifyOnly(c.publicKey)
		if err != nil {
			return nil, err
		}
	}
	return c.verify, nil
}

// SubjectPublicKeyInfo returns the public key in SPKI form.
func (c *Creator) SubjectPublicKeyInfo() (string, error) {
	cry, err := NewCryptoVerifyOnly(c.publicKey)
	if err != nil {
		return "", err
	}
	return cry.getSubjectPublicKeyInfo()
}

// Domain associated with the creator.
func (c *Creator) Domain() string { return c.domain }

func newCreator(
	domain string,
	privateKey string,
	publicKey string,
	name string) *Creator {
	var c Creator
	c.domain = domain
	c.privateKey = privateKey
	c.publicKey = publicKey
	c.name = name
	return &c
}
