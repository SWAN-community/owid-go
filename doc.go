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

// Package owid implements Open Web Id (OWID) in Go. An OWID is a small
// cryptographically signed data structure that records the domain of the
// party that created it, the date and time of creation to the nearest minute
// and a byte array payload.
//
// OWIDs are signed with ECDSA using the P-256 curve over a SHA-256 hash of
// the other fields. An OWID can be verified with the public key of the
// creator, which can be provided directly in PEM form or fetched over HTTP
// from the creator's domain.
//
// OWIDs can be chained together. When other OWIDs are passed to Create their
// bytes form part of the signed data, which binds the new OWID to them. The
// same OWIDs must be supplied again for verification to succeed.
//
// An OWID reaches calling code in one of two ways, being a read of bytes that
// already are one, or a Creator that creates and signs one in a single step.
// There is no exported constructor and the fields are read only, so an OWID
// cannot be held in an unsigned state, because an unsigned one is
// indistinguishable from a signed one to whatever handles it next.
//
// Bytes that are not an OWID are an ordinary result rather than a fault, so
// FromBase64, FromByteArray, FromBuffer and FromForm report why with a
// ParseError carrying a ParseStatus, which errors.As reaches. FromBuffer
// reads one frame from the front of a buffer that carries more after it and
// says nothing about what follows, while the others read a buffer holding one
// OWID and nothing else. Whether the signature is genuine is a separate
// question, answered by the SignatureStatus methods, which keep a signature
// that does not match apart from a check that could not be made at all.
//
// The package also provides HTTP handlers to register creators, serve public
// keys and verify OWIDs, along with storage implementations for AWS, Azure,
// GCP and the local file system.
//
// See https://github.com/SWAN-community/owid for the concepts behind OWID.
package owid
