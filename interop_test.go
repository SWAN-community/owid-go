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
	"encoding/base64"
	"fmt"
	"testing"
)

/**
 * Cross language interoperability tests. The fixtures embedded in this file
 * were signed by the Rust and .NET implementations of OWID on 2026-06-12
 * using throwaway P-256 keys created for that purpose. At generation time
 * the full matrix was verified, with each of the Go, .NET, JavaScript and
 * Rust implementations verifying all of the fixtures and rejecting tampered
 * copies.
 */

// Public key in SPKI PEM format for the Rust fixtures.
const interopRustPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQcDroVnBAGAvy1SyUz4MyFxP16ki
aPLulPz92rmbDbFKB6p0xl3iatZQ0uADa+F9cZeemLKtlfPaaue/KvNQOw==
-----END PUBLIC KEY-----
`

// Rust OWID with the ASCII payload "example".
const interopRustSimple = "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAHAAAAZXhhbXBsZQtzvD+xirWingyfDxbykxurSxK4XdixdGR5lR0xnHmv2IFSsVCub2Jd1jRg/vQJ8XnXuNljRp/ErjSOMMQo5CI="

// Rust OWID with a UTF-8 payload containing multi byte characters.
const interopRustUTF8 = "A3J1c3Quc3dhbi1kZW1vLnVrAD69MwAWAAAAWsO8cmljaCDinaQgT1dJRCDCo+KCrDHenDds+W587AzXpBb94gmLOloeBJTlHnjCkez4Dz2yAPtjcoQ6M/ZUWDIobtJHE5n9a81pTsn/Kvi74Azzx4s="

// Public key in SPKI PEM format for the .NET fixtures.
const interopDotnetPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ
A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==
-----END PUBLIC KEY-----`

// .NET OWID with the ASCII payload "example".
const interopDotnetSimple = "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU2FJbLjof8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcwEetjN1z9UWzyh0w=="

// .NET OWID with a UTF-8 payload containing multi byte characters.
const interopDotnetUTF8 = "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lEIMKj4oKsVuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg2rKMybcsAxMmnrDtF2xsk1cJvHgoIYpSJJQ=="

// The expected text of the UTF-8 payload fixtures. Go strings are UTF-8 so
// the payload bytes convert directly with PayloadAsString.
const interopUTF8Payload = "Zürich ❤ OWID £€"

// interopFixture groups the OWIDs signed by another implementation with the
// public key needed to verify them.
type interopFixture struct {
	language  string
	publicKey string
	simple    string
	utf8      string
}

var interopFixtures = []interopFixture{
	{
		language:  "rust",
		publicKey: interopRustPublicKey,
		simple:    interopRustSimple,
		utf8:      interopRustUTF8,
	},
	{
		language:  "dotnet",
		publicKey: interopDotnetPublicKey,
		simple:    interopDotnetSimple,
		utf8:      interopDotnetUTF8,
	},
}

// TestOWIDInteropVerify verifies that the simple and UTF-8 OWIDs signed by
// the other implementations pass verification with the public key of the
// creator.
func TestOWIDInteropVerify(t *testing.T) {
	for _, f := range interopFixtures {
		c := interopCrypto(t, &f)
		for _, a := range []string{f.simple, f.utf8} {
			o := interopOWID(t, a)
			v, err := o.VerifyWithCrypto(c)
			if err != nil {
				t.Fatal(err)
			}
			if v != true {
				t.Fatal(fmt.Errorf(
					"'%s' OWID did not pass verification", f.language))
			}
		}
	}
}

// TestOWIDInteropTampered verifies that flipping the final signature byte of
// each fixture causes verification to fail.
func TestOWIDInteropTampered(t *testing.T) {
	for _, f := range interopFixtures {
		c := interopCrypto(t, &f)
		for _, a := range []string{f.simple, f.utf8} {
			b, err := base64.StdEncoding.DecodeString(a)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)-1] = b[len(b)-1] ^ 0xFF
			o, err := FromByteArray(b)
			if err != nil {
				t.Fatal(err)
			}
			v, err := o.VerifyWithCrypto(c)
			if err != nil {
				t.Fatal(err)
			}
			if v != false {
				t.Fatal(fmt.Errorf(
					"'%s' tampered OWID should not pass verification",
					f.language))
			}
		}
	}
}

// TestOWIDInteropPayload verifies that the UTF-8 fixture payload decodes to
// the expected text.
func TestOWIDInteropPayload(t *testing.T) {
	for _, f := range interopFixtures {
		o := interopOWID(t, f.utf8)
		if o.PayloadAsString() != interopUTF8Payload {
			t.Errorf("expected payload '%s', found '%s'",
				interopUTF8Payload, o.PayloadAsString())
		}
	}
}

// TestOWIDInteropBase64 verifies that each fixture re-serialized with
// AsBase64 matches the original base 64 string exactly.
func TestOWIDInteropBase64(t *testing.T) {
	for _, f := range interopFixtures {
		for _, a := range []string{f.simple, f.utf8} {
			o := interopOWID(t, a)
			s, err := o.AsBase64()
			if err != nil {
				t.Fatal(err)
			}
			if s != a {
				t.Errorf("'%s' OWID did not round trip", f.language)
			}
		}
	}
}

// interopCrypto returns a verify only Crypto instance for the public key of
// the fixture.
func interopCrypto(t *testing.T, f *interopFixture) *Crypto {
	c, err := NewCryptoVerifyOnly(f.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// interopOWID decodes the base 64 string into an OWID.
func interopOWID(t *testing.T, value string) *OWID {
	o, err := FromBase64(value)
	if err != nil {
		t.Fatal(err)
	}
	return o
}
