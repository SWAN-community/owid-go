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
	"strconv"
	"time"
)

const (
	owidEmpty    byte = 0
	owidVersion1 byte = 1
	owidVersion2 byte = 2
	owidVersion3 byte = 3
)

var client *http.Client

func init() {
	client = &http.Client{}
}

// OWID structure which can be used as a node in a tree.
// OWID is a claim about who created some data and when, and it is only worth
// anything because it is signed. A caller therefore cannot build one: the
// fields are unexported, so an instance arrives either from parsing bytes that
// were already a complete OWID, or from a Creator that signs one into
// existence. There is deliberately no way to assemble a half made one, because
// an unsigned OWID is indistinguishable from a signed one to the code
// downstream of it, and the difference only surfaces later when a verification
// fails somewhere nobody is watching.
//
// The accessors return copies of the byte slices for the same reason. A parsed
// OWID's signature covers its fields as they arrived, so a caller writing into
// a returned slice would hold something whose signature no longer describes it.
type OWID struct {
	version   byte      // The byte version of the OWID. Version 1 only.
	domain    string    // Domain associated with the creator.
	date      time.Time // The date and time to the nearest minute in UTC of the creation.
	payload   []byte    // Array of bytes that form the identifier.
	signature []byte    // Signature for this OWID and it's ancestor from the creator.
}

// Version returns the byte version of the OWID.
func (o *OWID) Version() byte { return o.version }

// Domain returns the domain associated with the creator.
func (o *OWID) Domain() string { return o.domain }

// Date returns the creation date to the nearest minute in UTC.
func (o *OWID) Date() time.Time { return o.date }

// Payload returns a copy of the bytes that form the identifier.
func (o *OWID) Payload() []byte {
	c := make([]byte, len(o.payload))
	copy(c, o.payload)
	return c
}

// Signature returns a copy of the signature for this OWID.
func (o *OWID) Signature() []byte {
	c := make([]byte, len(o.signature))
	copy(c, o.signature)
	return c
}

// Age returns the number of complete minutes that have elapsed since the OWID
// was created. The granularity is to the nearest minute.
func (o *OWID) Age() int {
	return int(time.Since(o.date).Minutes())
}

// PayloadAsString converts the payload to a string.
func (o *OWID) PayloadAsString() string {
	return string(o.payload)
}

// PayloadAsPrintable returns a string representation of the payload.
func (o *OWID) PayloadAsPrintable() string {
	return fmt.Sprintf("%x ", o.payload)
}

// PayloadAsBase64 returns the payload as a URL encoded base 64 string.
func (o *OWID) PayloadAsBase64() string {
	return base64.StdEncoding.EncodeToString(o.payload)
}

// newOwid builds an unsigned instance for the creator to sign. Not
// exported: an unsigned OWID must never reach calling code, because it is
// indistinguishable from a signed one to whatever handles it next. A domain
// longer than the published maximum is refused here so the caller is told
// when they supply the domain, which is before anything is signed, rather
// than when the OWID is later serialised.
func newOwid(
	domain string,
	date time.Time,
	payload []byte) (*OWID, error) {
	err := checkDomainLength(domain)
	if err != nil {
		return nil, err
	}
	var o OWID
	o.version = owidVersion3
	o.domain = domain
	o.date = date
	o.payload = payload
	return &o, nil
}

// Sign this OWID and and any other OWIDs using the Crypto instance provided.
// sign is not exported, for the reason given on Creator.sign.
func (o *OWID) sign(c *Crypto, others []*OWID) error {
	b, err := o.dataForCrypto(others)
	if err != nil {
		return err
	}
	o.signature, err = c.SignByteArray(b)
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
	return c.VerifyByteArray(b, o.signature)
}

// SignatureStatusWithPublicKey says whether the signature is genuine, or why
// that could not be decided.
//
// Only two of the answers are about the signature. The rest say the question
// could not be answered, which is a different thing and must never be reported
// as a forgery. A key that cannot be decoded leaves the signature unjudged,
// and a caller acting on "invalid" would reject good identifiers during an
// outage. On 30 August 2026 the key end points served PEM a strict parser
// rejects and every offline verification failed, with the keys and the
// identifiers both fine.
func (o *OWID) SignatureStatusWithPublicKey(
	public string,
	others ...*OWID) SignatureStatus {
	if public == "" {
		return KeyUnavailable
	}
	if len(o.signature) != signatureLength {
		return InvalidSignatureLength
	}
	c, err := NewCryptoVerifyOnly(public)
	if err != nil {
		// The key is the thing at fault, not the identifier.
		return InvalidKey
	}
	return o.SignatureStatusWithCrypto(c, others...)
}

// SignatureStatusWithCrypto is SignatureStatusWithPublicKey for a key that has
// already been read.
func (o *OWID) SignatureStatusWithCrypto(
	c *Crypto,
	others ...*OWID) SignatureStatus {
	if c == nil {
		return KeyUnavailable
	}
	if len(o.signature) != signatureLength {
		return InvalidSignatureLength
	}
	b, err := o.dataForCrypto(others)
	if err != nil {
		// The identifier is fine and the question could not be put.
		return VerificationError
	}
	matched, err := c.VerifyByteArray(b, o.signature)
	if err != nil {
		return VerificationError
	}
	if matched {
		return SignatureValid
	}
	return SignatureInvalid
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
		Host:   o.domain,
		Path:   fmt.Sprintf("/owid/api/v%d/public-key", o.version)}
	q := u.Query()
	q.Set("format", "pkcs")
	// Send the OWID's own date so the creator can return the signing key that
	// was current when this OWID was created, letting OWIDs signed before a
	// key rotation still verify. Creators that do not support dated lookup
	// ignore the parameter and return the current key.
	if !o.date.Before(ioDateBase) {
		minutes := uint32(o.date.Sub(ioDateBase).Minutes())
		q.Set("date", strconv.FormatUint(uint64(minutes), 10))
	}
	u.RawQuery = q.Encode()
	r, err := client.Get(u.String())
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return false, fmt.Errorf(
			"Domain '%s' return code '%d'",
			o.domain,
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
	err = writeSignature(f, o.signature)
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
	length, err := o.byteLength(true)
	if err != nil {
		return nil, err
	}
	var f bytes.Buffer
	f.Grow(length)
	err = o.ToBuffer(&f)
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
	if b == nil {
		return nil, newParseError(MissingInput, "")
	}
	o, consumed, err := parseFrom(b.Bytes(), false)
	if err != nil {
		return nil, err
	}
	// Take only what the envelope occupied. What follows may be the next one,
	// so it is left where it is for the caller to read next.
	b.Next(consumed)
	return o, nil
}

// FromByteArray creates a single OWID from the byte array.
func FromByteArray(b []byte) (*OWID, error) {
	return parseExact(b)
}

// FromBase64 creates a single OWID from the base 64 string.
func FromBase64(value string) (*OWID, error) {
	if value == "" {
		return nil, newParseError(MissingInput, "")
	}
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		// Not valid base 64 is one of the expected outcomes on a public
		// surface, so it is reported with the same vocabulary as everything
		// else rather than as an encoding package error the caller would have
		// to recognise separately.
		return nil, newParseError(InvalidBase64, "")
	}
	return FromByteArray(b)
}

// FromForm extracts the base64 string from the form and returns the OWID.
// If the key is missing or the string is not valid then an error is returned.
func FromForm(q *url.Values, n string) (*OWID, error) {
	if q == nil || q.Get(n) == "" {
		return nil, newParseError(MissingInput, "key '%s' missing from form", n)
	}
	o, err := FromBase64(q.Get(n))
	if err != nil {
		// Wrapped, not formatted. Formatting turned the reason into text and
		// a caller could no longer reach it with errors.As, so this surface
		// alone reported no status.
		return nil, fmt.Errorf("key '%s': %w", n, err)
	}
	return o, nil
}

// dataForCrypto adds the fields from this OWID to the byte buffer without
// the signature. Adds all the bytes of the others to the data.
func (o *OWID) dataForCrypto(others []*OWID) ([]byte, error) {
	length, err := o.byteLength(false)
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if other != nil {
			otherLength, lengthErr := other.byteLength(true)
			if lengthErr != nil {
				return nil, lengthErr
			}
			length, lengthErr = addByteLength(length, otherLength)
			if lengthErr != nil {
				return nil, lengthErr
			}
		}
	}
	var f bytes.Buffer
	f.Grow(length)
	err = o.toBufferNoSignature(&f)
	if err != nil {
		return nil, err
	}
	for _, a := range others {
		if a != nil {
			err = a.ToBuffer(&f)
			if err != nil {
				return nil, err
			}
		}
	}
	return f.Bytes(), nil
}

// byteLength returns the exact number of bytes serialization will write.
// Calculating it first lets bytes.Buffer allocate once for a matching large
// payload instead of repeatedly growing and copying its backing array.
func (o *OWID) byteLength(includeSignature bool) (int, error) {
	var dateLength int
	switch o.version {
	case owidVersion1:
		dateLength = 2
	case owidVersion2, owidVersion3:
		dateLength = 4
	default:
		return 0, fmt.Errorf("version '%d' not supported", o.version)
	}
	if uint64(len(o.payload)) > uint64(^uint32(0)) {
		return 0, fmt.Errorf(
			"payload length '%d' exceeds the unsigned 32 bit limit",
			len(o.payload))
	}
	if includeSignature && len(o.signature) != signatureLength {
		return 0, fmt.Errorf(
			"provided signature length '%d' not compaitable with '%d' "+
				"OWID signature length",
			len(o.signature),
			signatureLength)
	}
	length := 0
	parts := []int{1, len(o.domain), 1, dateLength, 4, len(o.payload)}
	if includeSignature {
		parts = append(parts, signatureLength)
	}
	for _, part := range parts {
		var err error
		length, err = addByteLength(length, part)
		if err != nil {
			return 0, err
		}
	}
	return length, nil
}

func addByteLength(left int, right int) (int, error) {
	maxInt := int(^uint(0) >> 1)
	if right < 0 || left > maxInt-right {
		return 0, fmt.Errorf("OWID byte length exceeds Go int capacity")
	}
	return left + right, nil
}

func fromBuffer(b *bytes.Buffer, o *OWID) error {
	var err error
	o.domain, err = readString(b)
	if err != nil {
		return err
	}
	o.date, err = readDate(b, o.version)
	if err != nil {
		return err
	}
	o.payload, err = readPayload(b)
	if err != nil {
		return err
	}
	o.signature, err = readSignature(b)
	if err != nil {
		return err
	}
	return nil
}

func (o *OWID) toBufferNoSignature(b *bytes.Buffer) error {
	err := writeByte(b, o.version)
	if err != nil {
		return err
	}
	err = writeString(b, o.domain)
	if err != nil {
		return err
	}
	err = writeDate(b, o.date, o.version)
	if err != nil {
		return err
	}
	err = writeByteArray(b, o.payload)
	if err != nil {
		return err
	}
	return nil
}
