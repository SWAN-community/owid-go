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
	"encoding/json"
	"fmt"
	"time"
)

const (
	owidVersion = 1
)

// OWID structure
type OWID struct {
	Version   byte      `json:"version"`   // The byte version of the OWID. Version 1 only.
	Domain    string    `json:"domain"`    // Domain associated with the creator
	Signature string    `json:"signature"` // Signature for the date AND payload bytes from the creator
	Date      time.Time `json:"date"`      // The date and time to the nearest minute in UTC of the creation
	Payload   []byte    `json:"payload"`   // Array of bytes that form the identifier
}

// PayloadAsString converts the payload to a string
func (o *OWID) PayloadAsString() string {
	return string(o.Payload)
}

// PayloadAsPrintable returns a string representation of the payload
func (o *OWID) PayloadAsPrintable() string {
	return fmt.Sprintf("%x", o.Payload)
}

// NewOwid creates a new instance of the OWID structure
func NewOwid(
	domain string,
	signature string,
	date time.Time,
	payload []byte) (*OWID, error) {
	var o = OWID{
		owidVersion,
		domain,
		signature,
		date,
		payload}

	return &o, nil
}

// Encode encodes this OWID as a JSON string.
func (o *OWID) Encode() (string, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// EncodeAsBase64 gets the Base64 representation of this OWID
func (o *OWID) EncodeAsBase64() (string, error) {
	var buf bytes.Buffer
	err := o.writeToBuffer(&buf)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeFromBase64 decodes a Base 64 string into an OWID
func DecodeFromBase64(owid string) (*OWID, error) {
	var o OWID
	b, err := base64.RawURLEncoding.DecodeString(owid)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(b)
	o.setFromBuffer(buf)
	if err != nil {
		return nil, err
	}
	return &o, nil
}

func (o *OWID) setFromBuffer(b *bytes.Buffer) error {
	var err error
	o.Version, err = readByte(b)
	if err != nil {
		return err
	}
	o.Domain, err = readString(b)
	if err != nil {
		return err
	}
	o.Signature, err = readString(b)
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
	return nil
}

func (o *OWID) writeToBuffer(b *bytes.Buffer) error {
	err := writeByte(b, o.Version)
	if err != nil {
		return err
	}
	err = writeString(b, o.Domain)
	if err != nil {
		return err
	}
	err = writeString(b, o.Signature)
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
