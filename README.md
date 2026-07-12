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
	"time"

	owid "github.com/SWAN-community/owid-go"
)

func main() {

	// Create a new key pair for the creator domain.
	crypto, err := owid.NewCrypto()
	if err != nil {
		panic(err)
	}

	// Create and sign an OWID containing the payload.
	o, err := owid.NewOwid("example.com", time.Now().UTC(), []byte("example"))
	if err != nil {
		panic(err)
	}
	err = o.Sign(crypto, nil)
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
of the creator, or by fetching the public key from the creator's domain.

```go
valid, err := o.VerifyWithPublicKey(publicKeyPem)

// Fetches the key from https://[o.Domain]/owid/api/v3/public-key.
valid, err = o.Verify("https")
```

OWIDs can be chained by passing other OWIDs to the sign operation. The same
OWIDs must be provided again for verification to succeed.

```go
root, _ := owid.NewOwid("example.com", time.Now().UTC(), []byte("root"))
root.Sign(crypto, nil)

child, _ := owid.NewOwid("example.com", time.Now().UTC(), []byte("child"))
child.Sign(crypto, []*owid.OWID{root})

// True only when the same others are supplied in the same order.
valid, _ := child.VerifyWithCrypto(crypto, []*owid.OWID{root})
```

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
fixtures that prove the wire format and signatures are portable. The AWS,
Azure and GCP storage backends are not covered by tests as they require
cloud credentials.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
