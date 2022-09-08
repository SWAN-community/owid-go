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
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestPerformanceSigning performance reporting for signing operations.
func TestPerformanceSigning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signing performance in short mode")
		return
	}
	seconds := 1
	for l := 0; l <= 2000; l += 1000 {
		t.Run(
			fmt.Sprintf("%ds %d", seconds, l),
			func(t *testing.T) {
				testPerformanceSigning(t, time.Duration(seconds)*time.Second, l)
			})
	}
}

// TestPerformanceVerify performance reporting for verify operations.
func TestPerformanceVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping verify performance in short mode")
		return
	}
	seconds := 1
	for l := 0; l <= 2000; l += 1000 {
		t.Run(
			fmt.Sprintf("%ds %d", seconds, l),
			func(t *testing.T) {
				testPerformanceVerify(t, time.Duration(seconds)*time.Second, l)
			})
	}
}

// testPerformanceSigning reports the number of signings complete in the
// duration.
func testPerformanceVerify(t *testing.T, d time.Duration, l int) {
	b := &ByteArray{Data: []byte(strings.Repeat("#", l))}
	s := NewTestDefaultSigner(t)
	o, err := s.CreateOWIDandSign(b)
	if err != nil {
		t.Fatal(err)
	}
	err = o.Validate()
	if err != nil {
		t.Fatal(err)
	}
	m := fmt.Sprintf("completed '%d' verifications in '%v' with length '%d'",
		testPerformanceVerifyLoop(t, d, s, o),
		d,
		l)
	t.Log(m)
}

func testPerformanceSigning(t *testing.T, d time.Duration, l int) {
	b := &ByteArray{Data: []byte(strings.Repeat("#", l))}
	s := NewTestDefaultSigner(t)
	m := fmt.Sprintf("completed '%d' signings in '%v' with length '%d'",
		testPerformanceSignLoop(t, s, d, b),
		d,
		l)
	t.Log(m)
}

// testPerformanceLoop creates a signer and then loops for the duration signing
// the test data returning the number of iterations that could be completed in
// the duration.
func testPerformanceSignLoop(
	t *testing.T,
	s *Signer,
	d time.Duration,
	b Marshaler) int {
	e := time.Now().Add(d)
	i := 0
	for time.Now().Before(e) {
		o, err := s.CreateOWIDandSign(b)
		if err != nil {
			t.Fatal(err)
		}
		err = o.Validate()
		if err != nil {
			t.Fatal(err)
		}
		i++
	}
	return i
}

// testPerformanceVerifyLoop verifies the provided OWID using the signer for the
// duration provided. Returns the number of verifications that were complete.
func testPerformanceVerifyLoop(
	t *testing.T,
	d time.Duration,
	s *Signer,
	o *OWID) int {
	e := time.Now().Add(d)
	i := 0
	for time.Now().Before(e) {
		v, err := s.Verify(o)
		if !v {
			t.Fatal("OWID failed verification")
		}
		if err != nil {
			t.Fatal(err)
		}
		i++
	}
	return i
}
