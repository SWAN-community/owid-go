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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

/**
 * All the public and support methods associated with the signing.
 * Nothing to do with the web or HTTP.
 */

// Crypto structure containing the public and private keys
type Crypto struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// NewCrypto creates an new instance of the Crypto structure and generates
//  a public / private key pair used to sign and verify OWIDs
func NewCrypto() (*Crypto, error) {
	var c Crypto
	privateKey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}
	c.publicKey = &privateKey.PublicKey
	c.privateKey = privateKey
	return &c, nil
}

// NewCryptoSignOnly creates a new instance of the Crypto structure for signing
// OWIDs only.
func NewCryptoSignOnly(private string) (*Crypto, error) {
	var c Crypto
	privateKey, err := convertBytesToPrivateKey([]byte(private))
	if err != nil {
		return nil, err
	}
	c.privateKey = privateKey
	return &c, nil
}

// NewCryptoVerifyOnly creates a new instance of the Crypto structure
// for Verifying OWIDs only.
func NewCryptoVerifyOnly(public string) (*Crypto, error) {
	var c Crypto
	publicKey, err := convertBytesToPublicKey([]byte(public))
	if err != nil {
		return nil, err
	}
	c.publicKey = publicKey
	return &c, nil
}

//SignByteArray signs the byte array with the public key of the crypto provider.
func (c *Crypto) SignByteArray(data []byte) ([]byte, error) {
	if c.privateKey == nil && c.publicKey != nil {
		return nil, errors.New(
			"This instance of Crypto cannot be used to generate a signature")
	}
	h := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		c.privateKey,
		crypto.SHA256,
		h[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// VerifyByteArray returns true if the signature is valid for the data.
func (c *Crypto) VerifyByteArray(data []byte, sig []byte) (bool, error) {
	if c.publicKey == nil {
		return false, errors.New(
			"This instance of Crypto cannot be used to verify a signature")
	}
	h := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(
		c.publicKey,
		crypto.SHA256,
		h[:],
		sig)
	if err != nil {
		return false, err
	}
	return true, nil
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
				Type:  "RSA PUBLIC KEY",
				Bytes: spki,
			},
		),
	), nil
}

func (c Crypto) publicKeyToPemString() string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(c.publicKey),
			},
		),
	)
}

func (c Crypto) privateKeyToPemString() string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
			},
		),
	)
}

func cipherToPemString(cipher []byte) string {
	return string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "MESSAGE",
				Bytes: cipher,
			},
		),
	)
}

func decodePEMBlockBytes(keyBytes []byte) ([]byte, error) {
	var err error

	block, _ := pem.Decode(keyBytes)
	blockBytes := block.Bytes
	ok := x509.IsEncryptedPEMBlock(block)

	if ok {
		blockBytes, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}

		return blockBytes, nil
	}

	return blockBytes, nil
}

func convertBytesToPrivateKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	blockBytes, err := decodePEMBlockBytes(keyBytes)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func convertBytesToPublicKey(keyBytes []byte) (*rsa.PublicKey, error) {
	blockBytes, err := decodePEMBlockBytes(keyBytes)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(blockBytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
