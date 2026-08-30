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
	"encoding/binary"
	"fmt"
	"time"
)

// The base year for all dates encoded with the io time methods.
var ioDateBase = time.Date(2020, time.Month(1), 1, 0, 0, 0, 0, time.UTC)

// The maximum length of an OWID signature in bytes.
const signatureLength = 64
const halfSignatureLength = signatureLength / 2

// maximumDomainLength is the greatest number of characters a creator domain
// may contain. RFC 1035 section 2.3.4, "Size limits", restricts the total
// length of a domain name to 255 octets or less, counting the label octets
// and the length octet that precedes each label. An OWID stores the
// presentation form of the name, being the text "example.com", where the
// dots take the place of those label length octets and the trailing root
// octet has no text equivalent, so the same limit is two characters shorter
// here.
const maximumDomainLength = 253

// readString reads the creator domain, being the text of the domain
// followed by a zero terminator. The terminator came from the sender, so
// the search for it stops at maximumDomainLength rather than running to the
// end of the buffer, which means the cost of a buffer with no terminator is
// bounded by the constant and not by the length of the input. A domain
// longer than the maximum and a domain with no terminator are refused the
// same way, because neither has a terminator inside the window, and nothing
// is consumed when either is refused.
func readString(b *bytes.Buffer) (string, error) {
	w := b.Bytes()
	if len(w) > maximumDomainLength+1 {
		w = w[:maximumDomainLength+1]
	}
	i := bytes.IndexByte(w, 0)
	if i < 0 {
		if len(w) > maximumDomainLength {
			return "", fmt.Errorf(
				"domain has no terminator in the first '%d' bytes, so it "+
					"is either longer than the '%d' character maximum or "+
					"has no terminator at all",
				len(w),
				maximumDomainLength)
		}
		return "", fmt.Errorf(
			"domain has no terminator in the '%d' bytes present",
			len(w))
	}
	b.Next(i + 1)
	return string(w[:i]), nil
}

// checkDomainLength refuses a creator domain longer than the published
// maximum. Go counts the length of a string in bytes and the reader walks
// bytes, so the two halves measure the same thing and a name written with
// characters outside the ASCII range is held to the same number of bytes
// the reader will search.
func checkDomainLength(domain string) error {
	if len(domain) > maximumDomainLength {
		return fmt.Errorf(
			"domain length '%d' exceeds the '%d' character maximum",
			len(domain),
			maximumDomainLength)
	}
	return nil
}

func readSignature(b *bytes.Buffer) ([]byte, error) {
	v := b.Next(int(signatureLength))
	if len(v) != signatureLength {
		return nil, fmt.Errorf(
			"signature length '%d' not compaitable with '%d' OWID signature "+
				"length",
			len(v),
			signatureLength)
	}
	return v, nil
}

func writeSignature(b *bytes.Buffer, v []byte) error {
	if len(v) != signatureLength {
		return fmt.Errorf(
			"provided signature length '%d' not compaitable with '%d' "+
				"OWID signature length",
			len(v),
			signatureLength)
	}
	return writeByteArrayNoLength(b, v)
}

// readByteArray reads a length prefixed byte array. The count came from
// the sender, so a count beyond the bytes present is refused rather than
// returning a short slice that the caller would take for the whole array.
// Nothing is allocated from the count, as Next returns a view of the
// buffer.
func readByteArray(b *bytes.Buffer) ([]byte, error) {
	l, err := readUint32(b)
	if err != nil {
		return nil, err
	}
	if uint64(l) > uint64(b.Len()) {
		return nil, fmt.Errorf(
			"byte array length '%d' exceeds the '%d' bytes present",
			l,
			b.Len())
	}
	return b.Next(int(l)), nil
}

// readPayload reads the OWID payload. The declared length came from the
// sender, so it is checked against the bytes present before anything is
// sized by it. The declared length must leave at least the 64 byte
// signature after the payload. FromBuffer consumes exactly one OWID and
// leaves any framed bytes after it for its caller; FromByteArray separately
// requires that no bytes remain.
func readPayload(b *bytes.Buffer) ([]byte, error) {
	l, err := readUint32(b)
	if err != nil {
		return nil, err
	}
	remaining := b.Len()
	if uint64(l)+signatureLength > uint64(remaining) {
		return nil, fmt.Errorf(
			"OWID payload length '%d' exceeds the '%d' bytes "+
				"present, of which the final '%d' must be the signature",
			l,
			remaining,
			signatureLength)
	}
	return b.Next(int(l)), nil
}

func writeByteArray(b *bytes.Buffer, v []byte) error {
	if uint64(len(v)) > uint64(^uint32(0)) {
		return fmt.Errorf(
			"payload length '%d' exceeds the unsigned 32 bit limit",
			len(v))
	}
	err := writeUint32(b, uint32(len(v)))
	if err != nil {
		return err
	}
	return writeByteArrayNoLength(b, v)
}

func writeByteArrayNoLength(b *bytes.Buffer, v []byte) error {
	l, err := b.Write(v)
	if err == nil {
		if l != len(v) {
			return fmt.Errorf(
				"mismatched lengths '%d' and '%d'",
				l,
				len(v))
		}
	}
	return err
}

func readDate(b *bytes.Buffer, v byte) (time.Time, error) {
	switch v {
	case owidVersion1:
		return readDateV1(b)
	case owidVersion2:
		return readDateV2(b)
	case owidVersion3:
		return readDateV2(b)
	default:
		return time.Time{}, fmt.Errorf("Date version '%d' is invalid", v)
	}
}

func readDateV1(b *bytes.Buffer) (time.Time, error) {
	h, err := b.ReadByte()
	if err != nil {
		return time.Time{}, err
	}
	l, err := b.ReadByte()
	if err != nil {
		return time.Time{}, err
	}
	d := int(h)<<8 | int(l)
	return ioDateBase.Add(time.Duration(d) * time.Hour * 24), nil
}

func readDateV2(b *bytes.Buffer) (time.Time, error) {
	i, err := readUint32(b)
	if err != nil {
		return time.Time{}, err
	}
	return ioDateBase.Add(time.Duration(i) * time.Minute), nil
}

func writeDate(b *bytes.Buffer, t time.Time, v byte) error {
	switch v {
	case owidVersion1:
		return writeDateV1(b, t)
	case owidVersion2:
		return writeDateV2(b, t)
	case owidVersion3:
		return writeDateV2(b, t)
	default:
		return fmt.Errorf("date version '%d' is invalid", v)
	}
}

func writeDateV1(b *bytes.Buffer, t time.Time) error {
	i := int(t.Sub(ioDateBase).Hours() / 24)
	err := writeByte(b, byte(i>>8))
	if err != nil {
		return err
	}
	return writeByte(b, byte(i&0x00FF))
}

func writeDateV2(b *bytes.Buffer, t time.Time) error {
	return writeUint32(b, uint32(t.Sub(ioDateBase).Minutes()))
}

func readByte(b *bytes.Buffer) (byte, error) {
	d := b.Next(1)
	if len(d) != 1 {
		return 0, fmt.Errorf("'%d' bytes incorrect for Byte", len(d))
	}
	return d[0], nil
}

func writeByte(b *bytes.Buffer, i byte) error {
	return b.WriteByte(i)
}

func readUint32(b *bytes.Buffer) (uint32, error) {
	d := b.Next(4)
	if len(d) != 4 {
		return 0, fmt.Errorf("'%d' bytes incorrect for Uint32", len(d))
	}
	return binary.LittleEndian.Uint32(d), nil
}

func writeUint32(b *bytes.Buffer, i uint32) error {
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, i)
	l, err := b.Write(v)
	if err == nil {
		if l != len(v) {
			return fmt.Errorf(
				"mismatched lengths '%d' and '%d'",
				l,
				len(v))
		}
	}
	return err
}

// writeString writes the creator domain, being the text of the domain
// followed by a zero terminator. A domain longer than the published maximum
// is refused here as well as at the points where a domain enters the
// library, so a value that arrives by another route, such as an assignment
// to the exported Domain field or JSON unmarshalling, cannot reach the wire
// in a form this same library would refuse to read back.
func writeString(b *bytes.Buffer, s string) error {
	err := checkDomainLength(s)
	if err != nil {
		return err
	}
	l, err := b.WriteString(s)
	if err == nil {

		// Validate the number of bytes written matches the number of bytes in
		// the string.
		if l != len(s) {
			return fmt.Errorf(
				"Mismatched lengths '%d' and '%d'",
				l,
				len(s))
		}

		// Write the null terminator.
		b.WriteByte(0)
	}
	return err
}
