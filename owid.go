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
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	owidVersion = 1
)

// OWID structure which can be used as a node in a tree.
type OWID struct {
	Version   byte      `json:"version"`   // The byte version of the OWID. Version 1 only.
	Domain    string    `json:"domain"`    // Domain associated with the creator.
	Signature []byte    `json:"signature"` // Signature for this OWID and it's ancestor from the creator.
	Date      time.Time `json:"date"`      // The date and time to the nearest minute in UTC of the creation.
	Payload   []byte    `json:"payload"`   // Array of bytes that form the identifier.
}

// PayloadAsString converts the payload to a string.
func (o *OWID) PayloadAsString() string {
	return string(o.Payload)
}

// PayloadAsPrintable returns a string representation of the payload.
func (o *OWID) PayloadAsPrintable() string {
	return fmt.Sprintf("%x ", o.Payload)
}

// PayloadAsBase64 returns the payload as a URL encoded base 64 string.
func (o *OWID) PayloadAsBase64() string {
	return base64.URLEncoding.EncodeToString(o.Payload)
}

// NewOwid creates a new unsigned instance of the OWID structure.
func NewOwid(
	domain string,
	date time.Time,
	payload []byte) (*OWID, error) {
	var o OWID
	o.Version = owidVersion
	o.Domain = domain
	o.Date = date
	o.Payload = payload
	return &o, nil
}

// Sign this OWID and and any other OWIDs using the Crypto instance provided.
func (o *OWID) Sign(c *Crypto, others []*OWID) error {
	b, err := o.dataForCrypto(others)
	if err != nil {
		return err
	}
	o.Signature, err = c.SignByteArray(b)
	if err != nil {
		return err
	}
	return nil
}

// VerifyWithCrypto this OWID and any other OWIDs are valid.
func (o *OWID) VerifyWithCrypto(c *Crypto, others []*OWID) (bool, error) {
	b, err := o.dataForCrypto(others)
	if err != nil {
		return false, err
	}
	return c.VerifyByteArray(b, o.Signature)
}

// VerifyWithPublicKey this OWID and it's ancestors using the public key in PEM
// format provided.
func (o *OWID) VerifyWithPublicKey(
	public string,
	others ...*OWID) (bool, error) {
	c, err := NewCryptoVerifyOnly(public)
	if err != nil {
		return false, err
	}
	return o.VerifyWithCrypto(c, others)
}

// Verify this OWID and it's ancestors by fetching the public key from the
// domain associated with the OWID.
func (o *OWID) Verify(scheme string) (bool, error) {
	r, err := http.Get(fmt.Sprintf(
		"%s://%s/owid/api/v%d/public-key?format=pkcs",
		scheme,
		o.Domain,
		o.Version))
	if err != nil {
		return false, err
	}
	if r.StatusCode != http.StatusOK {
		return false, fmt.Errorf(
			"Domain '%s' return code '%d'",
			o.Domain,
			r.StatusCode)
	}
	v, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	return o.VerifyWithPublicKey(string(v))
}

// ToBuffer appends the OWID to the buffer provided.
func (o *OWID) ToBuffer(f *bytes.Buffer) error {
	err := o.toBufferNoSignature(f)
	if err != nil {
		return err
	}
	err = writeByteArray(f, o.Signature)
	if err != nil {
		return err
	}
	return nil
}

// AsByteArray returns the OWID as a byte array.
func (o *OWID) AsByteArray() ([]byte, error) {
	var f bytes.Buffer
	err := o.ToBuffer(&f)
	if err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// AsBase64 returns the OWID as a base 64 string.
func (o *OWID) AsBase64() (string, error) {
	b, err := o.AsByteArray()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// AsString returns the OWID as a base 64 string or the text of any error
// message.
func (o *OWID) AsString() string {
	s, err := o.AsBase64()
	if err != nil {
		return err.Error()
	}
	return s
}

// FromBuffer creates a single OWID from the buffer.
func FromBuffer(b *bytes.Buffer) (*OWID, error) {
	var o OWID
	var err error
	o.Version, err = readByte(b)
	if err != nil {
		return nil, err
	}
	switch o.Version {
	case 1:
		fromBufferV1(b, &o)
		break
	default:
		return nil, fmt.Errorf("Version '%d' not supported", o.Version)
	}
	return &o, nil
}

// FromByteArray creates a single OWID from the byte array.
func FromByteArray(b []byte) (*OWID, error) {
	return FromBuffer(bytes.NewBuffer(b))
}

// FromBase64 creates a single OWID from the base 64 string.
func FromBase64(value string) (*OWID, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return FromByteArray(b)
}

// dataForCrypto adds the fields from this OWID to the byte buffer without
// the signature. Adds all the bytes of the others to the data.
func (o *OWID) dataForCrypto(others []*OWID) ([]byte, error) {
	var f bytes.Buffer
	err := o.toBufferNoSignature(&f)
	if err != nil {
		return nil, err
	}
	if others != nil {
		for _, a := range others {
			if a != nil {
				err = a.ToBuffer(&f)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return f.Bytes(), nil
}

func fromBufferV1(b *bytes.Buffer, o *OWID) error {
	var err error
	o.Domain, err = readString(b)
	if err != nil {
		return err
	}
	o.Date, err = readDate(b)
	if err != nil {
		return err
	}
	o.Payload, err = readByteArray(b)
	if err != nil {
		return err
	}
	o.Signature, err = readByteArray(b)
	if err != nil {
		return err
	}
	return nil
}

func (o *OWID) toBufferNoSignature(b *bytes.Buffer) error {
	err := writeByte(b, o.Version)
	if err != nil {
		return err
	}
	err = writeString(b, o.Domain)
	if err != nil {
		return err
	}
	err = writeDate(b, o.Date)
	if err != nil {
		return err
	}
	err = writeByteArray(b, o.Payload)
	if err != nil {
		return err
	}
	return nil
}
