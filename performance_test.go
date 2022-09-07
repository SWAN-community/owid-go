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
	"testing"
	"time"
)

// TestPerformanceSigning performance reporting for signing operations.
func TestPerformanceSigning(t *testing.T) {
	t.Run("1s", func(t *testing.T) { testPerformanceSigning(t, time.Second) })
}

// TestPerformanceVerify performance reporting for verify operations.
func TestPerformanceVerify(t *testing.T) {
	t.Run("1s", func(t *testing.T) { testPerformanceVerify(t, time.Second) })
}

// testPerformanceSigning reports the number of signings complete in the
// duration.
func testPerformanceSigning(t *testing.T, d time.Duration) {
	s := NewTestDefaultSigner(t)
	o, err := s.CreateOWIDandSign(testByteArray)
	if err != nil {
		t.Fatal(err)
	}
	err = o.Validate()
	if err != nil {
		t.Fatal(err)
	}
	m := fmt.Sprintf("completed '%d' signings in '%v'",
		testPerformanceVerifyLoop(t, d, s, o),
		d)
	t.Log(m)
}

func testPerformanceVerify(t *testing.T, d time.Duration) {
	m := fmt.Sprintf("completed '%d' verifications in '%v'",
		testPerformanceSignLoop(t, d),
		d)
	t.Log(m)
}

// testPerformanceLoop creates a signer and then loops for the duration signing
// the test data returning the number of iterations that could be completed in
// the duration.
func testPerformanceSignLoop(t *testing.T, d time.Duration) int {
	s := NewTestDefaultSigner(t)
	e := time.Now().Add(d)
	i := 0
	for time.Now().Before(e) {
		o, err := s.CreateOWIDandSign(testByteArray)
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
