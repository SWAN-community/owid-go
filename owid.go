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
	"net/url"
	"time"
)

const (
	owidEmpty    byte = 0
	owidVersion1 byte = 1
	owidVersion2 byte = 2
)

var client *http.Client

func init() {
	client = &http.Client{}
}

// OWID structure which can be used as a node in a tree.
type OWID struct {
	Version   byte      `json:"version"`   // The byte version of the OWID. Version 1 only.
	Domain    string    `json:"domain"`    // Domain associated with the creator.
	Date      time.Time `json:"date"`      // The date and time to the nearest minute in UTC of the creation.
	Payload   []byte    `json:"payload"`   // Array of bytes that form the identifier.
	Signature []byte    `json:"signature"` // Signature for this OWID and it's ancestor from the creator.
}

// Age returns the number of complete minutes that have elapsed since the OWID
// was created. The granularity is to the nearest minute.
func (o *OWID) Age() int {
	return int(time.Now().Sub(o.Date).Minutes())
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
	return base64.StdEncoding.EncodeToString(o.Payload)
}

// NewOwid creates a new unsigned instance of the OWID structure.
func NewOwid(
	domain string,
	date time.Time,
	payload []byte) (*OWID, error) {
	var o OWID
	o.Version = owidVersion2
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
	u := url.URL{
		Scheme: scheme,
		Host:   o.Domain,
		Path:   fmt.Sprintf("/owid/api/v%d/public-key", o.Version)}
	q := u.Query()
	q.Set("format", "pkcs")
	u.RawQuery = q.Encode()
	r, err := client.Get(u.String())
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
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
	err = writeSignature(f, o.Signature)
	if err != nil {
		return err
	}
	return nil
}

// EmptyToBuffer writes an empty OWID marker. Used to indicate optional OWIDs
// in byte arrays.
func EmptyToBuffer(f *bytes.Buffer) error {
	return writeByte(f, owidEmpty)
}

// ToQuery adds the OWID to a query string.
func (o *OWID) ToQuery(k string, q *url.Values) error {
	v, err := o.AsBase64()
	if err != nil {
		return err
	}
	q.Set(k, v)
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
	case owidEmpty:
		break
	case owidVersion1:
		fromBuffer(b, &o)
	case owidVersion2:
		fromBuffer(b, &o)
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

// FromForm extracts the base64 string from the form and returns the OWID.
// If the key is missing or the string is not valid then an error is returned.
func FromForm(q *url.Values, n string) (*OWID, error) {
	if q.Get(n) == "" {
		return nil, fmt.Errorf("Key '%s' missing from form", n)
	}
	o, err := FromBase64(q.Get(n))
	if err != nil {
		return nil, fmt.Errorf("Key '%s' %s", n, err.Error())
	}
	return o, nil
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

func fromBuffer(b *bytes.Buffer, o *OWID) error {
	var err error
	o.Domain, err = readString(b)
	if err != nil {
		return err
	}
	o.Date, err = readDate(b, o.Version)
	if err != nil {
		return err
	}
	o.Payload, err = readByteArray(b)
	if err != nil {
		return err
	}
	o.Signature, err = readSignature(b)
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
	err = writeDate(b, o.Date, o.Version)
	if err != nil {
		return err
	}
	err = writeByteArray(b, o.Payload)
	if err != nil {
		return err
	}
	return nil
}
