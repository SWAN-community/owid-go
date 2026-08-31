/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
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

import "fmt"

// ParseStatus says why reading an OWID succeeded or failed.
//
// Malformed data arriving from outside is expected, not exceptional. An OWID
// is read from whatever a caller was given, which on a public endpoint means
// anything at all, so every one of these outcomes is a normal result. Go
// already reports failure by returning an error rather than panicking, so what
// was missing was not the shape but the reason: a caller could tell that a
// parse failed but not why, short of matching on message text, which is not
// something code should have to do.
//
// These names are the cross-language vocabulary, so a failure means the same
// thing whichever language read the bytes.
type ParseStatus int

const (
	// Parsed means the bytes form a structurally valid OWID. It says nothing
	// about the signature, which is a separate question answered separately.
	Parsed ParseStatus = iota

	// MissingInput means nothing was supplied to parse.
	MissingInput

	// InvalidBase64 means the string is not valid base 64, so there are no
	// bytes to read.
	InvalidBase64

	// UnsupportedVersion means the first byte names a version this
	// implementation does not know.
	UnsupportedVersion

	// UnexpectedEnd means the data stopped in the middle of a field. Distinct
	// from ByteCountMismatch, which is a declaration that disagrees with data
	// that is all present.
	UnexpectedEnd

	// InvalidDomainEncoding means the creator domain is not terminated, or is
	// longer than the published maximum.
	InvalidDomainEncoding

	// ByteCountMismatch means the declared payload byte count disagrees with
	// the bytes actually present. Checked before anything is sized by the
	// declaration, so a sender cannot make a reader allocate by claiming a
	// large payload it did not send.
	ByteCountMismatch

	// ImplementationCapacityExceeded means the envelope is structurally
	// consistent but larger than this runtime can hold. Not a fault in the
	// data, and deliberately distinct from the data being wrong, because the
	// same bytes may be readable elsewhere.
	ImplementationCapacityExceeded

	// AbsentNode is the version 0 marker, which stands for an absent node
	// inside a stream. It is not an OWID and never produces one, because it
	// carries no signature and so can never verify. A framed read reports it
	// and moves past its one byte, so a caller walking a run of frames can
	// tell an absent node from a malformed one, which is the distinction the
	// marker exists for. The whole buffer read reports it too, because the
	// byte means the same thing wherever it appears; calling it an
	// unsupported version was inaccurate, since version 0 is supported and
	// meaningful.
	AbsentNode

	// MalformedEnvelope is a fallback for the genuinely unclassified, not a
	// substitute for naming a failure that is already understood.
	MalformedEnvelope
)

// String returns the cross-language name of the status.
func (s ParseStatus) String() string {
	switch s {
	case Parsed:
		return "Parsed"
	case MissingInput:
		return "MissingInput"
	case InvalidBase64:
		return "InvalidBase64"
	case UnsupportedVersion:
		return "UnsupportedVersion"
	case UnexpectedEnd:
		return "UnexpectedEnd"
	case InvalidDomainEncoding:
		return "InvalidDomainEncoding"
	case ByteCountMismatch:
		return "ByteCountMismatch"
	case ImplementationCapacityExceeded:
		return "ImplementationCapacityExceeded"
	case AbsentNode:
		return "AbsentNode"
	case MalformedEnvelope:
		return "MalformedEnvelope"
	default:
		return fmt.Sprintf("ParseStatus(%d)", int(s))
	}
}

// ParseError is returned when bytes are not an OWID, and carries the reason in
// a form code can branch on.
//
// Use errors.As to reach it:
//
//	o, err := owid.FromBase64(value)
//	var pe *owid.ParseError
//	if errors.As(err, &pe) && pe.Status == owid.ByteCountMismatch {
//	    // the declaration disagreed with the bytes present
//	}
type ParseError struct {
	// Status is the specific reason the bytes are not an OWID.
	Status ParseStatus

	// Detail adds what is known about the failure. It never contains the
	// input itself, so that logging a parse failure cannot log whatever an
	// untrusted sender chose to put in it.
	Detail string
}

func (e *ParseError) Error() string {
	if e.Detail == "" {
		return e.Status.String()
	}
	return e.Status.String() + ": " + e.Detail
}

// newParseError builds an error carrying the status and an optional detail.
func newParseError(status ParseStatus, format string, a ...interface{}) error {
	detail := ""
	if format != "" {
		detail = fmt.Sprintf(format, a...)
	}
	return &ParseError{Status: status, Detail: detail}
}

// SignatureStatus is the outcome of asking whether an OWID's signature is
// genuine.
//
// Only two of these say anything about the signature itself. The rest say the
// question could not be answered, which is a different thing and must never be
// reported as a forgery. A key that cannot be fetched, a key that cannot be
// decoded, or a provider that fails leaves the signature unjudged, and a
// caller acting on "invalid" would reject good identifiers during an outage.
//
// On 30 August 2026 the key endpoints published PEM a strict parser rejects
// and every offline verification against them failed. The keys and the
// identifiers were both fine. Reported as InvalidKey that reads as the
// operational fault it was; reported as SignatureInvalid it would have read as
// an attack.
type SignatureStatus int

const (
	// SignatureValid means the signature is genuine for this data and key.
	SignatureValid SignatureStatus = iota

	// SignatureInvalid means the signature is well formed and does not match.
	// The only status that means the identifier should be distrusted.
	SignatureInvalid

	// InvalidSignatureLength means a signature field of the wrong length
	// reached a verification surface directly. A signature truncated in raw
	// external input never gets this far, because there the envelope never
	// formed and the read reports a parse failure instead, being
	// ByteCountMismatch on a whole buffer where every byte is present and
	// UnexpectedEnd on a frame that stopped early.
	InvalidSignatureLength

	// KeyUnavailable means no key could be obtained, or none covers the
	// identifier's date. The signature was never examined.
	KeyUnavailable

	// InvalidKey means key material arrived but cannot be decoded, imported or
	// used as the required type. The fault is in the key, not the identifier.
	InvalidKey

	// VerificationError means the check could not be completed for a reason
	// that is not the identifier's fault.
	VerificationError
)

// String returns the cross-language name of the status.
func (s SignatureStatus) String() string {
	switch s {
	case SignatureValid:
		return "SignatureValid"
	case SignatureInvalid:
		return "SignatureInvalid"
	case InvalidSignatureLength:
		return "InvalidSignatureLength"
	case KeyUnavailable:
		return "KeyUnavailable"
	case InvalidKey:
		return "InvalidKey"
	case VerificationError:
		return "VerificationError"
	default:
		return fmt.Sprintf("SignatureStatus(%d)", int(s))
	}
}
