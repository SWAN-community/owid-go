# ![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID)

## Overview

Open Web Id (OWID) is a small cryptographically signed identifier. Each OWID
records the domain of the party that created it, the date and time of
creation to the nearest minute and a byte array payload. The signature is
created with ECDSA using the P-256 curve over a SHA-256 hash of the other
fields, so any change to the OWID after signing can be detected. OWIDs can
also be chained together so that one OWID is bound to others at the moment of
signing. Read the [OWID](https://github.com/SWAN-community/owid) project to
learn more about the concepts behind this implementation.

## Scope of this implementation

This repository contains the full Go implementation of OWID. It can create,
sign and verify OWIDs, serve the HTTP endpoints used to register creators,
publish public keys and verify OWIDs, and persist creator key pairs using
AWS, Azure, GCP or local file storage backends.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null-terminated domain is at most
253 characters, following the 255 octet limit in RFC 1035 section 2.3.4, which
the presentation form stored here holds two characters fewer of, so that field
occupies at most 254 bytes with its terminator. The payload is the part with
no useful bound, so the protocol alone is not an application input limit for
the complete envelope.

This package validates that the declared payload length agrees with the bytes
present before it takes a view of the payload. A large declaration without
the corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The in-memory APIs remain subject to the target's `int`, address-space and
available-memory limits. Applications accepting untrusted OWIDs must choose
limits suitable for their use case and enforce them before buffering the
binary form or decoding Base64. An implementation capacity failure or an
application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope, and
allow for the domain and the other OWID fields as well as the payload. The
fields of a parsed OWID are read only and `Payload()` hands back a copy, so a
size check that must not copy the bytes belongs on the transport input before
the envelope is buffered or the base 64 decoded. The parser cannot choose
either limit on behalf of the application.

## Installation

```
go get github.com/SWAN-community/owid-go
```

## Usage

Create a key pair, sign an OWID and verify it.

```go
package main

import (
	"fmt"

	owid "github.com/SWAN-community/owid-go"
)

func main() {

	// Create a new key pair for the creator domain.
	crypto, err := owid.NewCrypto()
	if err != nil {
		panic(err)
	}

	// Create and sign an OWID containing the payload. Creation and signing
	// are one step: an OWID cannot exist in an unsigned state, because an
	// unsigned one is indistinguishable from a signed one to whatever
	// handles it next.
	creator, err := owid.NewCreator("example.com", crypto)
	if err != nil {
		panic(err)
	}
	o, err := creator.Create([]byte("example"))
	if err != nil {
		panic(err)
	}

	// Output the OWID as a base 64 string for transmission.
	s, err := o.AsBase64()
	if err != nil {
		panic(err)
	}
	fmt.Println(s)

	// Decode the OWID and verify it with the public key.
	n, err := owid.FromBase64(s)
	if err != nil {
		panic(err)
	}
	valid, err := n.VerifyWithCrypto(crypto, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(valid)
}
```

An OWID received from another party can be verified with the PEM public key
of the creator, or by fetching the public key from the creator's domain. The
key a creator publishes for its own domain comes from
`Creator.SubjectPublicKeyInfo`, and is what the public-key endpoint serves.

```go
valid, err := o.VerifyWithPublicKey(publicKeyPem)

// Fetches the key from https://[o.Domain()]/owid/api/v3/public-key, sending
// the OWID's own date so that a creator which has rotated its key can return
// the key that was current when this OWID was created.
valid, err = o.Verify("https")
```

OWIDs can be chained by passing other OWIDs to the create operation. The same
OWIDs must be provided again for verification to succeed.

```go
root, _ := creator.Create([]byte("root"))
child, _ := creator.Create([]byte("child"), root)

// True only when the same others are supplied in the same order.
valid, _ := child.VerifyWithCrypto(crypto, []*owid.OWID{root})
```

## Reading an OWID

An OWID reaches calling code in one of two ways, being a read of bytes that
already are one, or a `Creator` that creates and signs one in a single step.
There is no exported constructor, the fields are read only, and the accessors
hand back copies of the byte slices, so an OWID cannot be held in an unsigned
state and nothing a caller does to a returned slice can leave an OWID whose
signature no longer describes it.

Bytes arriving from outside that are not an OWID are an ordinary result rather
than a fault, so a read reports why with a `ParseError` carrying a
`ParseStatus`, and nothing panics. Reach the status with `errors.As`, so that
code branches on a named reason instead of on message text. The detail on a
`ParseError` never contains any part of the input, which means logging a
failure cannot log whatever an untrusted sender chose to put in it.

```go
o, err := owid.FromBase64(value)
if err != nil {
	var pe *owid.ParseError
	if errors.As(err, &pe) {
		switch pe.Status {
		case owid.ByteCountMismatch:
			// The declared payload does not match what arrived.
		case owid.UnexpectedEnd:
			// The data stopped part way through.
		case owid.AbsentNode:
			// The marker for a node that is not there.
		default:
			// Every other reason the bytes are not an OWID.
		}
	}
	return
}
fmt.Println(o.Domain(), o.Date(), o.PayloadAsString())
```

The statuses are the same names in every OWID implementation, so a failure
means the same thing whichever language read the bytes.

| Status | Meaning |
|--------|---------|
| `Parsed` | The bytes are a structurally valid OWID, and nothing is said about the signature. A read that succeeds hands back the OWID and no error, so this member is the vocabulary's name for success rather than a value a caller is given |
| `MissingInput` | Nothing was supplied to read |
| `InvalidBase64` | The text is not base 64, so there are no bytes to read. The standard encoding with padding is expected |
| `UnsupportedVersion` | The first byte names a version this implementation does not know |
| `UnexpectedEnd` | The data stopped in the middle of a field, or a frame's declared payload runs past the bytes supplied |
| `InvalidDomainEncoding` | The creator domain is not terminated within the 253 character maximum |
| `ByteCountMismatch` | The declared payload byte count disagrees with the bytes present. Checked before anything is sized by the declaration, so a sender cannot make a reader allocate by claiming a payload it did not send |
| `ImplementationCapacityExceeded` | The envelope is consistent but larger than this runtime can hold. Not a fault in the data, because the same bytes may be readable elsewhere |
| `AbsentNode` | The version 0 marker, standing for a node that is not there |
| `MalformedEnvelope` | Kept for the genuinely unclassified, and not a substitute for naming a reason that is already understood |

`FromForm` reads a base 64 value out of form values and names the missing key,
wrapping any `ParseError` rather than turning it into text, so `errors.As`
reaches the status there as well.

Reading is not verifying. A successful read says the bytes are a structurally
valid OWID and says nothing about the signature, which is a separate question
with a separate answer.

### A whole buffer, and a frame

`FromBase64` and `FromByteArray` read a buffer that holds one OWID and nothing
else, so the declared payload must leave exactly the signature the version
requires. A byte after the signature is a `ByteCountMismatch`, because with
every byte present the declaration and the data disagree.

`FromBuffer` reads one frame from the front of a buffer that may carry more
after it, and advances the buffer by what the frame occupied. It requires the
declared payload and the signature to be present and says nothing about what
follows, because what follows may be the next envelope rather than rubbish. A
frame that stops short is therefore an `UnexpectedEnd`, being data that
stopped early, which tells a caller reading a source that is still arriving
that waiting for more bytes would help. Nothing is consumed when a frame is
refused, so a caller that stops at a malformed frame finds the buffer where it
was.

```go
var framed bytes.Buffer
for _, payload := range []string{"first", "second"} {
	o, err := creator.Create([]byte(payload))
	if err != nil {
		return err
	}
	if err := o.ToBuffer(&framed); err != nil {
		return err
	}
}

for framed.Len() > 0 {
	o, err := owid.FromBuffer(&framed)
	if err != nil {
		var pe *owid.ParseError
		if errors.As(err, &pe) && pe.Status == owid.AbsentNode {
			// The frame said the node is not there, and the marker byte has
			// already been stepped over, so the next frame can be read.
			continue
		}
		return err
	}
	fmt.Println(o.PayloadAsString())
}
```

### The marker for a node that is not there

`EmptyToBuffer` writes a single zero byte standing for an absent node inside a
stream. It is not an OWID and no value is handed back for one, because it
carries no signature and so can never verify. Both reads report `AbsentNode`
rather than an unsupported version, as version 0 is supported and meaningful.
A framed read also steps over the one marker byte, so a caller walking a run
of frames reaches the next envelope and can tell an absent node from a
malformed frame, which is the distinction the marker exists for.

### Whether the signature is genuine

`SignatureStatusWithPublicKey` and `SignatureStatusWithCrypto` answer with a
`SignatureStatus`. Only two of the answers are about the signature itself, and
the rest say the question could not be put, which must never be reported as a
forgery. A key that cannot be fetched or decoded leaves the signature
unjudged, and a caller acting on "invalid" would reject good identifiers
during an outage.

| Status | Meaning |
|--------|---------|
| `SignatureValid` | The signature is genuine for this data and key |
| `SignatureInvalid` | The signature is well formed and does not match. The only answer that means the identifier should be distrusted |
| `InvalidSignatureLength` | A signature field of the wrong length reached the check. A signature truncated in raw external input never gets this far, because there the envelope never formed and the read reports a parse failure instead |
| `KeyUnavailable` | No key could be obtained, or none covers the identifier's date. The signature was never examined |
| `InvalidKey` | Key material arrived and cannot be decoded, imported or used as the required type. The fault is in the key, not the identifier |
| `VerificationError` | The check could not be completed for a reason that is not the identifier's fault |

`VerifyWithPublicKey`, `VerifyWithCrypto` and `Verify` answer the same
question as a boolean with an error, which is kept for callers that already
use it.

## Running a creator service

To run an OWID creator service use `AddHandlers` with a configuration, store
and access implementation.

```go
config := owid.NewConfig("appsettings.json")
store := owid.NewStore(config)
access := owid.NewAccessSimple([]string{"access-key"})
services := owid.NewServices(config, store, access)
owid.AddHandlers(services)
```

## HTTP endpoints

`AddHandlers` registers the following endpoints. The api routes are
registered for versions v1, v2 and v3.

| Endpoint | Description |
|----------|-------------|
| /owid/register | HTML form to register the host domain as an OWID creator |
| /owid/api/v3/creator | Returns the name, domain and public keys of the creator for the host domain |
| /owid/api/v3/public-key | Returns the creator's public key in PEM form, with the `format` parameter set to `spki` or `pkcs`. An optional `date` parameter (minutes since 2020-01-01 UTC, the OWID Date encoding) returns the key that was current at that date, or `404` if it predates the oldest key |
| /owid/api/v3/verify | Verifies the OWID in the `owid` parameter and returns JSON in the form `{"valid":true}` |

The same creator, public-key and verify paths are also registered under
`/owid/api/v1/` and `/owid/api/v2/` for backwards compatibility.

### Historical keys

By default the public-key endpoint serves the single key held by the creator
store and ignores `date`, which suits a creator that uses one long-lived key.
A creator that rotates its key can serve historical keys by supplying a
`PublicKeyStore` via `Services.SetPublicKeyStore`. The built-in
`NewDatedPublicKeyStore` applies the selection rule (the newest key created on
or before the requested date) over a set of dated keys per domain.

### Requiring authentication (optional)

The OWID specification leaves authentication to the implementor: a creator
MAY require a credential on the public-key and creator endpoints, for
example to tie key access to a subscription. Supply an authorizer via
`Services.SetAuthorizer`; without one the endpoints stay open. The verify
and register endpoints are not affected.

```go
services.SetAuthorizer(func(r *http.Request) error {
	if r.Header.Get("X-Api-Key") == "" {
		return fmt.Errorf("an API key is required to call this endpoint")
	}
	return nil
})
```

When the authorizer returns an error the endpoint responds with status 401
and the error text as the body. The 51Degrees cloud, for example, requires
a resource key or license key on these endpoints and meters each call.

## Testing

```
go test ./...
```

The tests cover creation, signing, verification, serialization, chaining, the
node tree and the HTTP handlers. The suite also verifies externally signed
fixtures that prove the wire format and signatures are portable. Every parse
and signature status is either produced by a test or named as unreachable
with the reason, and a test walks both vocabularies so that a status added
later cannot be left silently untested. The examples in this file are run as
tests in `readme_test.go`, so documentation that has drifted away from the
code fails the build rather than waiting for a reader to find it. The AWS,
Azure and GCP storage backends are not covered by tests as they require
cloud credentials.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
