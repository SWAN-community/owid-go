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
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/SWAN-community/common-go"
)

// Client used to obtain information from the domain associated with the OWID.
var client *http.Client

func init() {
	client = &http.Client{}
}

// OWID structure which can be used as a node in a tree.
type OWID struct {
	Version   byte      // The byte version of the OWID.
	Domain    string    // Domain associated with the creator.
	TimeStamp time.Time // The date and time to the nearest minute in UTC of the creation.
	Signature []byte    // Signature for this OWID and it's ancestor from the creator.
	Target    Marshaler // Instance of the object that contains the data related to the OWID.
}

// AgeInMinutes returns the number of complete minutes that have elapsed since
// the OWID was created.
func (o *OWID) AgeInMinutes() int {
	return int(time.Since(o.TimeStamp).Minutes())
}

// GetTimeStampInMinutes returns the date that the OWID was created as the
// number of minutes since the common.IoDateBase epoch.
func (o *OWID) GetTimeStampInMinutes() uint32 {
	return common.GetDateInMinutes(o.TimeStamp)
}

// SetTimeStampInMinutes sets the timestamp in minutes from the
// common.IoDateBase epoch.
func (o *OWID) SetTimeStampInMinutes(t uint32) {
	o.TimeStamp = common.GetDateFromMinutes(uint32(t))
}

// NewUnsignedOwid creates a new unsigned instance of the OWID structure.
// returns the new OWID
func NewUnsignedOwid(
	domain string,
	date time.Time,
	target Marshaler) (*OWID, error) {
	return &OWID{
		Version:   owidVersion1,
		Domain:    domain,
		TimeStamp: date,
		Target:    target}, nil
}

// Validate the OWID data structure (not the same as Verify which checks the
// signature is valid) and returns an error instance if there is a problem.
func (o *OWID) Validate() error {
	if o.Signature == nil {
		return fmt.Errorf("signature missing")
	}
	if o.Domain == "" {
		return fmt.Errorf("domain missing")
	}
	if o.TimeStamp.Before(common.IoDateBase) {
		return fmt.Errorf("date older than base date")
	}
	v := false
	for _, i := range owidVersions {
		if o.Version == i {
			v = true
			break
		}
	}
	if !v {
		return fmt.Errorf("version '%d' invalid", o.Version)
	}
	return nil
}

// Sign the data provided with the crypto instance and update the signature of the OWID.
// crypto instance to use for signing
func (o *OWID) Sign(crypto *Crypto) error {
	d, err := o.Target.MarshalOwid()
	if err != nil {
		return err
	}
	o.Signature, err = crypto.SignByteArray(d)
	if err != nil {
		return err
	}
	return nil
}

// VerifyWithCrypto the signature in the OWID and the data provided.
// crypto instance to use for verification
// Returns true if the signature matches the data, otherwise false.
func (o *OWID) VerifyWithCrypto(crypto *Crypto) (bool, error) {
	d, err := o.Target.MarshalOwid()
	if err != nil {
		return false, err
	}
	return crypto.VerifyByteArray(d, o.Signature)
}

// VerifyWithPublicKey the signature in the OWID and the data provided using the
// public key.
// public key in PEM format
// Returns true if the signature matches the data, otherwise false.
func (o *OWID) VerifyWithPublicKey(public string) (bool, error) {
	c, err := NewCryptoVerifyOnly(public)
	if err != nil {
		return false, err
	}
	return o.VerifyWithCrypto(c)
}

// Verify this OWID and it's ancestors by fetching the public key from the
// domain in the OWID.
// scheme to use when fetching the public key from the domain in the OWID
// Returns true if the signature matches the data, otherwise false.
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
			"domain '%s' return code '%d'",
			o.Domain,
			r.StatusCode)
	}
	v, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	return o.VerifyWithPublicKey(string(v))
}

// MarshalJSON the OWID to conform to the OneKey source definition.
// https://github.com/OneKey-Network/addressability-framework/blob/main/mvp-spec/model/source.md
// Note: the version is added to the JSON with the intention of adding this to
// the source in OneKey in the future.
func (o *OWID) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["version"] = o.Version
	m["domain"] = o.Domain
	m["timestamp"] = o.GetTimeStampInMinutes()
	m["signature"] = base64.StdEncoding.EncodeToString(o.Signature)
	return json.Marshal(m)
}

// UnmarshalJSON from JSON which conforms to the OneKey source definition.
// https://github.com/OneKey-Network/addressability-framework/blob/main/mvp-spec/model/source.md
func (o *OWID) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}
	if v, ok := m["version"].(float64); ok {
		o.Version = byte(v)
	} else {
		o.Version = owidVersion1
	}
	if d, ok := m["domain"].(string); ok {
		o.Domain = d
	} else {
		return fmt.Errorf("domain missing")
	}
	if s, ok := m["signature"].(string); ok {
		o.Signature, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("signature missing")
	}
	if t, ok := m["timestamp"].(float64); ok {
		o.SetTimeStampInMinutes(uint32(t))
	} else {
		return fmt.Errorf("timestamp missing")
	}
	err = o.Validate()
	if err != nil {
		return err
	}
	return nil
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
	return common.WriteByte(f, owidEmpty)
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

// MarshalBinary returns the OWID as a byte array.
func (o *OWID) MarshalBinary() ([]byte, error) {
	var f bytes.Buffer
	err := o.ToBuffer(&f)
	if err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// AsBase64 returns the OWID as a base 64 string.
func (o *OWID) AsBase64() (string, error) {
	b, err := o.MarshalBinary()
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

// FromBuffer populates the OWID fields from the buffer provided.
func (o *OWID) FromBuffer(b *bytes.Buffer) error {
	var err error
	o.Version, err = common.ReadByte(b)
	if err != nil {
		return err
	}
	switch o.Version {
	case owidEmpty:
		// Used to indicate that the OWID is empty and yet to be populated.
		return nil
	case owidVersion1:
		return fromBufferV1(b, o)
	}
	return fmt.Errorf("version '%d' not supported", o.Version)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (o *OWID) UnmarshalBinary(data []byte) error {
	return o.FromBuffer(bytes.NewBuffer(data))
}

// FromByteArray creates a single OWID from the byte array with the data
// provided.
func FromByteArray(data []byte, m Marshaler) (*OWID, error) {
	return FromBuffer(bytes.NewBuffer(data), m)
}

// FromBase64 creates a single OWID from the base 64 string.
func FromBase64(value string, m Marshaler) (*OWID, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return FromByteArray(b, m)
}

// FromForm extracts the base64 string from the form and returns the OWID.
// If the key is missing or the string is not valid then an error is returned.
func FromForm(q *url.Values, key string, target Marshaler) (*OWID, error) {
	if q.Get(key) == "" {
		return nil, fmt.Errorf("key '%s' missing from form", key)
	}
	o, err := FromBase64(q.Get(key), target)
	if err != nil {
		return nil, fmt.Errorf("key '%s' %s", key, err.Error())
	}
	return o, nil
}

// FromBuffer creates a single OWID from the buffer and data.
func FromBuffer(b *bytes.Buffer, target Marshaler) (*OWID, error) {
	o := &OWID{Target: target}
	return o, o.FromBuffer(b)
}

func fromBufferV1(b *bytes.Buffer, o *OWID) error {
	var err error
	o.Domain, err = common.ReadString(b)
	if err != nil {
		return err
	}
	o.TimeStamp, err = common.ReadDateFromUInt32(b)
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
	err := common.WriteByte(b, o.Version)
	if err != nil {
		return err
	}
	err = common.WriteString(b, o.Domain)
	if err != nil {
		return err
	}
	err = common.WriteDateToUInt32(b, o.TimeStamp)
	if err != nil {
		return err
	}
	return nil
}

func (o *OWID) compare(other *OWID) bool {
	return o.Version == other.Version &&
		o.Domain == other.Domain &&
		o.GetTimeStampInMinutes() == other.GetTimeStampInMinutes() &&
		bytes.Equal(o.Signature, other.Signature)
}
