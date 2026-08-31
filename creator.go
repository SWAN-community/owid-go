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
	"encoding/json"
	"fmt"
	"time"
)

// Creator of Open Web Ids and immutable data.
type Creator struct {
	domain      string  // The registered domain name and key fields
	privateKey  string  // Private key in PEM format used to sign OWIDs
	publicKey   string  // Public key in PEM format used to verify OWIDs
	name        string  // The name of the entity associated with the domain
	contractURL string  // URL with the T&Cs associated with the creation of data
	sign        *Crypto // Cached crypto instance for signing
	verify      *Crypto // Cached crypto instance for verification
}

// Create returns a new signed OWID from the creator carrying the payload, and
// covering any others so that a tree can be verified as a whole.
//
// This is one of only two ways an OWID reaches calling code, the other being a
// successful parse. The creator owns the version, the domain, the date and the
// signature; a caller supplies the payload and nothing else, so there is no
// moment at which a partly built OWID exists for anyone to hold or pass on.
func (c *Creator) Create(payload []byte, others ...*OWID) (*OWID, error) {
	o, err := newOwid(c.domain, time.Now(), payload)
	if err != nil {
		return nil, err
	}
	if err = c.signOwid(o, others...); err != nil {
		return nil, err
	}
	return o, nil
}

// Sign the OWID by updating the signature field.
// sign is not exported. An OWID cannot exist in an unsigned state, so there
// is nothing outside this package for a caller to sign, and re-signing one
// that already exists would replace a signature the fields were read with.
func (c *Creator) signOwid(o *OWID, others ...*OWID) error {
	if c.domain != o.domain {
		return fmt.Errorf(
			"can't use creator '%s' to sign OWID for domain '%s'",
			c.domain,
			o.domain)
	}
	x, err := c.NewCryptoSignOnly()
	if err != nil {
		return err
	}
	return o.sign(x, others)
}

// CreateOWIDandSign creates the OWID with the payload and signs the result.
//
// Kept as the name callers already use. Create is the same operation named
// for what it does, and both now go through the one path, because creation
// and signing were never two steps a caller should be able to separate.
func (c *Creator) CreateOWIDandSign(
	payload []byte,
	others ...*OWID) (*OWID, error) {
	return c.Create(payload, others...)
}

// Verify the OWID and any other OWIDs are valid for this creator.
func (c *Creator) Verify(o *OWID, others ...*OWID) (bool, error) {
	if c.domain != o.domain {
		return false, fmt.Errorf(
			"Can't use creator '%s' to verify OWID for domain '%s'",
			c.domain,
			o.domain)
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

// MarshalJSON marshals a node to JSON without having to expose the fields in
// the node struct. This is achieved by converting a node to a map.
func (c *Creator) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"domain":       c.domain,
		"privateKey":   c.privateKey,
		"publicKey":    c.publicKey,
		"name":         c.name,
		"contractURL:": c.contractURL})
}

// UnmarshalJSON called by json.Unmarshall unmarshals a node from JSON and turns
// it into a new node. As the node is marshalled to JSON by converting it to a
// map, the unmarshalling from JSON needs to handle the type of each field
// correctly. A creator read back from a store this way does not pass
// through newCreator, so the domain length is checked here as well.
func (c *Creator) UnmarshalJSON(b []byte) error {
	var d map[string]string
	err := json.Unmarshal(b, &d)
	if err != nil {
		return err
	}
	err = checkDomainLength(d["domain"])
	if err != nil {
		return err
	}
	c.domain = d["domain"]
	c.privateKey = d["privateKey"]
	c.publicKey = d["publicKey"]
	c.name = d["name"]
	c.contractURL = d["contractURL"]
	return nil
}

// NewCreator returns a creator for the domain, holding the key pair it will
// sign with.
//
// A creator is now the only way to make an OWID, because an OWID cannot exist
// in an unsigned state, so this has to be reachable from outside the package.
// Before, a caller built an unsigned OWID directly and signed it afterwards,
// which left a window in which one existed with no signature and nothing to
// say it was not finished.
func NewCreator(domain string, crypto *Crypto) (*Creator, error) {
	if crypto == nil {
		return nil, fmt.Errorf("a crypto instance is required to sign with")
	}
	privateKey, err := crypto.privateKeyToPemString()
	if err != nil {
		return nil, err
	}
	publicKey, err := crypto.publicKeyToPemString()
	if err != nil {
		return nil, err
	}
	return newCreator(domain, privateKey, publicKey, "", "")
}

// newCreator returns a creator for the domain given. Every creator is built
// here, whether it comes from the registration end point or from a store, so
// a domain longer than the published maximum is refused here and the caller
// is told at that point rather than when the first OWID the creator makes is
// read by someone else.
func newCreator(
	domain string,
	privateKey string,
	publicKey string,
	name string,
	contractURL string) (*Creator, error) {
	err := checkDomainLength(domain)
	if err != nil {
		return nil, err
	}
	var c Creator
	c.domain = domain
	c.privateKey = privateKey
	c.publicKey = publicKey
	c.name = name
	c.contractURL = contractURL
	return &c, nil
}
