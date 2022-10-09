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

// cspell:ignore unmarshals unmarshalling SPKI

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Signer of Open Web Ids.
type Signer struct {
	Domain   string  `json:"domain"`   // The registered domain name and key field
	Name     string  `json:"name"`     // The common name of the signer
	TermsURL string  `json:"termsUrl"` // URL with the T&Cs associated with the signed data
	Keys     []*Keys `json:"keys"`     // The private and public keys associated with the signer
	current  *Keys   // The most recent keys in the array of keys
}

// Signer of Open Web Ids in a form that can be marshalled for providing public
// key information to other parties.
type SignerPublic struct {
	Domain     string       `json:"domain"`     // The registered domain name and key field
	Name       string       `json:"name"`       // The common name of the signer
	TermsURL   string       `json:"termsUrl"`   // URL with the T&Cs associated with the signed data
	PublicKeys []*PublicKey `json:"publicKeys"` // The public keys associated with the signer
}

// newSigner creates a new instance of the signer from the parameters provided.
// Internal only as consumers of the OWID package should not generate new keys.
// These have to persisted to permanent storage.
func newSigner(
	domain string,
	name string,
	termsURL string,
	keys *Keys) (*Signer, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain needed")
	}
	if name == "" {
		return nil, fmt.Errorf("name needed")
	}
	if termsURL == "" {
		return nil, fmt.Errorf("termsURL needed")
	}
	_, err := url.ParseRequestURI(termsURL)
	if err != nil {
		return nil, fmt.Errorf("termsURL invalid")
	}
	if keys == nil {
		return nil, fmt.Errorf("key pair needed")
	}

	// Create the initial signer.
	s := &Signer{
		Domain:   domain,
		Name:     name,
		TermsURL: termsURL,
		Keys:     []*Keys{keys}}

	return s, nil
}

// SortKeys in descending order of created date.
func (s *Signer) SortKeys() {
	sort.Slice(s.Keys, func(a, b int) bool {
		return s.Keys[a].Created.After(s.Keys[b].Created)
	})
}

// PublicKeys creates an array of the public key information.
func (s *Signer) PublicKeys() []*PublicKey {
	p := make([]*PublicKey, len(s.Keys))
	for i, k := range s.Keys {
		p[i] = &PublicKey{Key: k.PublicKey, Created: k.Created}
	}
	return p
}

// PublicSigner creates a new instance of a public signer.
func (s *Signer) PublicSigner() *SignerPublic {
	return &SignerPublic{
		Domain:     s.Domain,
		Name:       s.Name,
		TermsURL:   s.TermsURL,
		PublicKeys: s.PublicKeys()}
}

// Sign the OWID by updating the signature, timestamp, and domain fields.
// owid to update the signature
func (s *Signer) Sign(owid *OWID) error {
	c, err := s.NewCryptoSignOnly()
	if err != nil {
		return err
	}
	owid.Version = owidVersion1
	owid.Domain = s.Domain
	return owid.Sign(c)
}

// CreateOWIDandSign the OWID with the data from the marshaller provided.
// m instance that supports Marshaller for OWIDs
// Returns a new OWID for the signer and the marshaller provided
func (s *Signer) CreateOWIDandSign(m Marshaler) (*OWID, error) {
	o := &OWID{Target: m}
	err := s.Sign(o)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// Verify the OWID and any other OWIDs are valid for this public key signer.
// owid containing the signature to verify with the data
// Returns true if the signature is valid, otherwise false.
//
// The signer has multiple keys and all of them have to be tried against the
// signature before verification can be complete.
func (s *SignerPublic) Verify(owid *OWID) (bool, error) {
	err := verifyDomains(s.Domain, owid)
	if err != nil {
		return false, err
	}
	b := owid.getTimeStampWithTolerance()
	for i := len(s.PublicKeys) - 1; i >= 0; i-- {
		k := s.PublicKeys[i]
		if !k.Created.After(b) {
			r, err := owid.VerifyWithPublicKey(k.Key)
			if err != nil {
				return false, err
			}
			if r {
				return true, nil
			}
		}
	}
	return false, nil
}

// Verify the OWID and any other OWIDs are valid for this signer.
// owid containing the signature to verify with the data
// Returns true if the signature is valid, otherwise false.
//
// The signer has multiple keys and all of them have to be tried against the
// signature before verification can be complete.
func (s *Signer) Verify(owid *OWID) (bool, error) {
	err := verifyDomains(s.Domain, owid)
	if err != nil {
		return false, err
	}
	b := owid.getTimeStampWithTolerance()
	for i := len(s.Keys) - 1; i >= 0; i-- {
		k := s.Keys[i]
		if !k.Created.After(b) {
			p, err := k.NewCryptoVerifyOnly()
			if err != nil {
				return false, err
			}
			r, err := owid.VerifyWithCrypto(p)
			if err != nil {
				return false, err
			}
			if r {
				return true, nil
			}
		}
	}
	return false, nil
}

// NewCryptoSignOnly creates a new instance of the Crypto structure for signing
// OWIDs only.
func (s *Signer) NewCryptoSignOnly() (*Crypto, error) {
	k, err := s.currentKeys()
	if err != nil {
		return nil, err
	}
	return k.NewCryptoSignOnly()
}

// verifyDomains checks that the signer and OWID domains match. If they don't
// an error is returned with a message indicating the mismatch.
func verifyDomains(s string, o *OWID) error {
	if !strings.EqualFold(s, o.Domain) {
		return fmt.Errorf(
			"can't use signer '%s' with OWID '%s'",
			s,
			o.Domain)
	}
	return nil
}

// currentKeys gets the current keys to use for signing operations. The created
// date is used to determine the most recent and therefore the currently active
// set of keys. The implementation does not assume an order to the keys incase
// the structure was not created using the owid.NewSigner method.
func (s *Signer) currentKeys() (*Keys, error) {
	if s.current == nil {
		var c *Keys
		for _, k := range s.Keys {
			if c == nil || c.Created.Before(k.Created) {
				c = k
			}
		}
		s.current = c
		if c == nil {
			return nil, fmt.Errorf(
				"signer for domain '%s' contains no keys",
				s.Domain)
		}
	}
	return s.current, nil
}
