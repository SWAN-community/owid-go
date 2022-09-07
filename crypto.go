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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

/**
 * All the public and support methods associated with the signing.
 * Nothing to do with the web or HTTP.
 */

// Crypto structure containing the public and private keys
type Crypto struct {
	publicKey  *ecdsa.PublicKey
	privateKey *ecdsa.PrivateKey
}

// NewCrypto creates an new instance of the Crypto structure and generates
// a public / private key pair used to sign and verify OWIDs.
func NewCrypto() (*Crypto, error) {
	var c Crypto
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	c.publicKey = &k.PublicKey
	c.privateKey = k
	return &c, nil
}

// NewCryptoSignOnly creates a new instance of the Crypto structure for signing
// OWIDs only from the PEM provided.
// privatePem PEM format non password protected ECDSA private PEM key.
func NewCryptoSignOnly(privatePem string) (*Crypto, error) {
	var c Crypto
	block, _ := pem.Decode([]byte(privatePem))
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM key")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	c.privateKey = privateKey
	return &c, nil
}

// NewCryptoVerifyOnly creates a new instance of the Crypto structure
// for Verifying OWIDs only from the PEM key.
// publicPemKey PEM format ECDSA public PEM key.
func NewCryptoVerifyOnly(publicPemKey string) (*Crypto, error) {
	var c Crypto
	block, _ := pem.Decode([]byte(publicPemKey))
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM key")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	c.publicKey = publicKey.(*ecdsa.PublicKey)
	return &c, nil
}

// SignByteArray signs the byte array with the private key of the crypto
// provider.
func (c *Crypto) SignByteArray(data []byte) ([]byte, error) {
	if c.privateKey == nil && c.publicKey != nil {
		return nil, errors.New(
			"instance of Crypto cannot be used to generate a signature")
	}
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(
		rand.Reader,
		c.privateKey,
		h[:])
	if err != nil {
		return nil, err
	}
	signature := make([]byte, signatureLength)
	for i, b := range r.Bytes() {
		signature[i] = b
	}
	for i, b := range s.Bytes() {
		signature[i+halfSignatureLength] = b
	}
	return signature, nil
}

// VerifyByteArray returns true if the signature is valid for the data.
func (c *Crypto) VerifyByteArray(data []byte, sig []byte) (bool, error) {
	if c.publicKey == nil {
		return false, errors.New(
			"instance of Crypto cannot be used to verify a signature")
	}
	h := sha256.Sum256(data)
	var r, s big.Int
	r.SetBytes(sig[:32])
	s.SetBytes(sig[32:])
	return ecdsa.Verify(
		c.publicKey,
		h[:],
		&r,
		&s), nil
}

// getSubjectPublicKeyInfo returns the public key in SPKI format for use with
// JavaScript SubtleCrypto.importKey() method or other methods that require
// SPKI format public keys.
func (c *Crypto) getSubjectPublicKeyInfo() (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(c.publicKey)
	if err != nil {
		return "", err
	}
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: spki,
			},
		),
	), nil
}

func (c Crypto) publicKeyToPemString() (string, error) {
	return c.getSubjectPublicKeyInfo()
}

func (c Crypto) privateKeyToPemString() (string, error) {
	k, err := x509.MarshalECPrivateKey(c.privateKey)
	if err != nil {
		return "", err
	}
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: k,
			},
		),
	), nil
}
