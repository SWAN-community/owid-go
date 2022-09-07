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
	"time"
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

// UnmarshalJSON prevents the signer being unmarshalled. A safety feature to
// reduce the risk of accidental exposure of the private keys.
func (s *Signer) UnmarshalJSON(data []byte) error {
	return fmt.Errorf("signer can not be unmarshalled")
}

// MarshalJSON prevents the signer being marshalled. A safety feature to reduce
// the risk of accidental exposure of the private keys.
func (s *Signer) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("signer can not be marshalled")
}

// NewOwid returns a new unsigned OWID associated with the signer.
// target associated with the newly created OWID
// returns the new OWID ready to be signed
func (s *Signer) NewOwid(target Marshaler) (*OWID, error) {
	return NewUnsignedOwid(s.Domain, time.Now(), target)
}

// SortKeys in descending order of created date.
func (s *Signer) SortKeys() {
	sort.Slice(s.Keys, func(a, b int) bool {
		return s.Keys[a].Created.After(s.Keys[b].Created)
	})
}

// PublicKeys creates an array of the public key information.
func (s *Signer) PublicKeys() ([]*PublicKey, error) {
	p := make([]*PublicKey, len(s.Keys))
	for i, k := range s.Keys {
		p[i] = &PublicKey{PublicKey: k.PublicKey, Created: k.Created}
	}
	return p, nil
}

// Sign the OWID by updating the signature field.
// owid to update the signature
func (s *Signer) Sign(owid *OWID) error {
	c, err := s.NewCryptoSignOnly()
	if err != nil {
		return err
	}
	return owid.Sign(c)
}

// CreateOWIDandSign the OWID with the payload and signs the result.
// data to be signed
// Returns a new OWID for the signer.
func (s *Signer) CreateOWIDandSign(m Marshaler) (*OWID, error) {
	o, err := s.NewOwid(m)
	if err != nil {
		return nil, err
	}
	err = s.Sign(o)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// Verify the OWID and any other OWIDs are valid for this signer.
// owid containing the signature to verify with the data
// Returns true if the signature is valid, otherwise false.
//
// The signer has multiple keys and all of them have to be tried against the
// signature before verification can be complete. The keys are ordered based on
// proximity to the OWID date field and then tried in order.
func (s *Signer) Verify(owid *OWID) (bool, error) {
	err := verifyDomains(s, owid)
	if err != nil {
		return false, err
	}
	if len(s.Keys) == 1 {

		// There is only one key so no need to order anything.
		return s.Keys[0].verifyOWID(owid)
	} else {

		// Order the keys that were created before this OWID and then evaluate
		// them in order of proximity to the OWID date. The most likely key will
		// be the one that was created just before the OWID.
		for _, k := range orderKeys(s.Keys, owid.TimeStamp.Add(-time.Hour)) {
			v, err := k.verifyOWID(owid)
			if err != nil {
				return false, err
			}
			if v {
				return true, nil
			}
		}
	}
	return false, nil
}

// NewCryptoSignOnly creates a new instance of the Crypto structure
// for signing OWIDs only.
func (s *Signer) NewCryptoSignOnly() (*Crypto, error) {
	k, err := s.currentKeys()
	if err != nil {
		return nil, err
	}
	return k.NewCryptoSignOnly()
}

// verifyDomains checks that the signer and OWID domains match. If they don't
// an error is returned with a message indicating the mismatch.
func verifyDomains(s *Signer, o *OWID) error {
	if s.Domain != o.Domain {
		return fmt.Errorf(
			"can't use signer '%s' with OWID '%s'",
			s.Domain,
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
