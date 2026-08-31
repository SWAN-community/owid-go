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

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
)

// The way an envelope is handed in must not change the answer. The base 64
// surface only decodes and delegates, so the same bytes get the same status
// whichever way they arrive, and the only statuses unique to the text surface
// are the two that describe the text itself.
//
// This is asserted rather than left true by construction, because the two
// surfaces are what a caller chooses between and a future change could easily
// give one a check the other does not have.
func TestTheSurfacesAgree(t *testing.T) {
	c := contractCreator(t)
	o, err := c.Create([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}

	unknownVersion := append([]byte(nil), good...)
	unknownVersion[0] = 9

	cases := map[string][]byte{
		"a whole envelope":     good,
		"an unknown version":   unknownVersion,
		"one byte too many":    append(append([]byte(nil), good...), 0),
		"a byte short":         good[:len(good)-1],
		"stops inside a field": good[:3],
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, fromBytes := FromByteArray(raw)
			_, fromText := FromBase64(base64.StdEncoding.EncodeToString(raw))

			if (fromBytes == nil) != (fromText == nil) {
				t.Fatalf(
					"one surface accepted and the other refused: bytes=%v text=%v",
					fromBytes, fromText)
			}
			if fromBytes == nil {
				return
			}

			var a, b *ParseError
			if !errors.As(fromBytes, &a) || !errors.As(fromText, &b) {
				t.Fatalf("both should carry a status: %v and %v",
					fromBytes, fromText)
			}
			if a.Status != b.Status {
				t.Errorf(
					"the same bytes gave %s through the byte surface and %s "+
						"through the text surface",
					a.Status, b.Status)
			}
		})
	}
}

// The form surface wraps the text one, so the reason must survive the wrap.
// It did not: the reason was formatted into the message rather than wrapped,
// so errors.As could not reach it and this surface alone reported no status.
func TestTheFormSurfaceKeepsTheReason(t *testing.T) {
	q := url.Values{}
	q.Set("owid", "not base 64 at all!!")

	_, err := FromForm(&q, "owid")

	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("the reason should survive the wrap, got %v", err)
	}
	if pe.Status != InvalidBase64 {
		t.Errorf("expected InvalidBase64, got %s", pe.Status)
	}

	// And a key that is not there at all is nothing supplied.
	_, err = FromForm(&q, "absent")
	if !errors.As(err, &pe) || pe.Status != MissingInput {
		t.Errorf("expected MissingInput, got %v", err)
	}
}

// A framed reader may leave what follows for its caller, because in a stream
// the next bytes may be the next envelope rather than rubbish. The whole
// buffer surface must refuse the same input, because there nothing else could
// own those bytes.
func TestFramedAndWholeBufferDifferOnlyOnWhatFollows(t *testing.T) {
	c := contractCreator(t)
	first, err := c.Create([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Create([]byte("second"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	both := append(append([]byte(nil), a...), b...)

	// The whole buffer surface refuses it: the declaration cannot leave
	// exactly the signature when another envelope follows.
	if _, err := FromByteArray(both); err == nil {
		t.Error("two envelopes are not one whole OWID")
	}

	// The framed surface reads the first and leaves the second.
	buffer := bytes.NewBuffer(both)
	one, err := FromBuffer(buffer)
	if err != nil {
		t.Fatalf("the first envelope should read: %v", err)
	}
	if string(one.Payload()) != "first" {
		t.Errorf("expected the first payload, got %q", one.Payload())
	}
	two, err := FromBuffer(buffer)
	if err != nil {
		t.Fatalf("the second envelope should read: %v", err)
	}
	if string(two.Payload()) != "second" {
		t.Errorf("expected the second payload, got %q", two.Payload())
	}
	if buffer.Len() != 0 {
		t.Errorf("both envelopes should be consumed, %d bytes left",
			buffer.Len())
	}
}
