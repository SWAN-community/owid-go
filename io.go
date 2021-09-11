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

func readString(b *bytes.Buffer) (string, error) {
	s, err := b.ReadBytes(0)
	if err == nil {
		return string(s[0 : len(s)-1]), err
	}
	return "", err
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

func readByteArray(b *bytes.Buffer) ([]byte, error) {
	l, err := readUint32(b)
	if err != nil {
		return nil, err
	}
	return b.Next(int(l)), err
}

func writeByteArray(b *bytes.Buffer, v []byte) error {
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

func readTime(b *bytes.Buffer) (time.Time, error) {
	var t time.Time
	d, err := readByteArray(b)
	if err == nil {
		t.GobDecode(d)
	}
	return t, err
}

func writeTime(b *bytes.Buffer, t time.Time) error {
	d, err := t.GobEncode()
	if err != nil {
		return err
	}
	return writeByteArray(b, d)
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

func writeString(b *bytes.Buffer, s string) error {
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
