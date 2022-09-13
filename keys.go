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
	"sort"
	"time"
)

// PublicKey associated with the signer at a given point in time.
type PublicKey struct {
	PublicKey string    `json:"publicKey,omitempty"` // The public key in PEM format
	Created   time.Time `json:"created"`             // The date and time that the keys were created
}

// Keys associated with a signer at a given point in time.
type Keys struct {
	PrivateKey string    `json:"privateKey"` // The private key in PEM format
	PublicKey  string    `json:"publicKey"`  // The public key in PEM format
	Created    time.Time `json:"created"`    // The date and time that the keys were created
	sign       *Crypto   // The signing crypto provider
	verify     *Crypto   // The verification crypto provider
}

// Keys with domain is a structure that also includes the domain of the signer
// that the key relates to. Used when writing the keys to permanent storage.
type KeysWithDomain struct {
	*Keys
	Domain string `json:"domain"`
}

// Used to sort the keys to find the ones before the target date.
type keySort struct {
	index    int           // Index of the key in the array of keys
	duration time.Duration // Duration between the target date and the key date
}

// newKey creates a new key. Internal only as consumers of the OWID package
// should not generate new keys. These have to persisted to permanent storage.
func newKeys() (*Keys, error) {
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
	return &Keys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Created:    time.Now().UTC()}, nil
}

// NewCryptoSignOnly creates a new instance of the Crypto structure
// for signing OWIDs only.
func (k *Keys) NewCryptoSignOnly() (*Crypto, error) {
	if k.sign == nil {
		var err error
		k.sign, err = NewCryptoSignOnly(k.PrivateKey)
		if err != nil {
			return nil, err
		}
	}
	return k.sign, nil
}

// NewCryptoVerifyOnly creates a new instance of the Crypto structure
// for Verifying OWIDs only.
func (k *Keys) NewCryptoVerifyOnly() (*Crypto, error) {
	if k.verify == nil {
		var err error
		k.verify, err = NewCryptoVerifyOnly(k.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	return k.verify, nil
}

// SubjectPublicKeyInfo returns the public key in SPKI form.
func (k *Keys) SubjectPublicKeyInfo() (string, error) {
	c, err := k.NewCryptoVerifyOnly()
	if err != nil {
		return "", err
	}
	return c.getSubjectPublicKeyInfo()
}

// equal based on the public fields of the Keys structure.
func (k *Keys) equal(other *Keys) bool {
	return k.PrivateKey == other.PrivateKey &&
		k.PublicKey == other.PublicKey &&
		k.Created.Equal(other.Created)
}

// orderKeys creates an array of keys based on the time elapsed between the
// creation of the key and the time provided. Used to try the keys for
// verification using an order that is most likely to
// verification
func orderKeys(k []*Keys, t time.Time) []*Keys {

	// Build an array of keys that were created before the time provided.
	// Anything that was created after the time provided couldn't possibly
	// be relevant.
	d := make([]keySort, 0, len(k))
	for i := 0; i < len(k); i++ {
		v := t.Sub(k[i].Created)
		if v >= 0 {
			d = append(d, keySort{
				duration: k[i].Created.Sub(t),
				index:    i})
		}
	}

	// Sort the array of keys in ascending order of duration from the time
	// provided.
	sort.Slice(d, func(a, b int) bool { return d[a].duration > d[b].duration })

	// Copy the pointers to the keys that could verify the OWID into a new array
	// to be returned.
	n := make([]*Keys, len(d))
	for i := 0; i < len(d); i++ {
		n[i] = k[d[i].index]
	}
	return n
}

// verifyOWID verifies the OWID provided.
func (k *Keys) verifyOWID(o *OWID) (bool, error) {
	c, err := k.NewCryptoVerifyOnly()
	if err != nil {
		return false, err
	}
	v, err := o.VerifyWithCrypto(c)
	if err != nil {
		return false, err
	}
	if v {
		return true, nil
	}
	return false, nil
}
