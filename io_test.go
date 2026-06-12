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
	"fmt"
	"testing"
	"time"
)

func TestIoTime(t *testing.T) {
	d := time.Now().UTC()
	var b bytes.Buffer
	err := writeDate(&b, d, 2)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	i := b.Bytes()
	c := bytes.NewBuffer(i)
	r, err := readDate(c, 2)
	if err != nil {
		fmt.Println(err)
		t.Fail()
	}
	testCompareDate(t, r, d)
}

// TestIoTimeV2Minute verifies that a version 2 date round trip is precise to
// the minute.
func TestIoTimeV2Minute(t *testing.T) {
	testIoTimeMinute(t, owidVersion2)
}

// TestIoTimeV3Minute verifies that a version 3 date round trip is precise to
// the minute.
func TestIoTimeV3Minute(t *testing.T) {
	testIoTimeMinute(t, owidVersion3)
}

// TestIoTimeV1Day verifies that a version 1 date round trip is precise to
// the day, with the time of day discarded.
func TestIoTimeV1Day(t *testing.T) {
	d := time.Date(2021, time.Month(3), 4, 15, 30, 0, 0, time.UTC)
	e := time.Date(2021, time.Month(3), 4, 0, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	err := writeDate(&b, d, owidVersion1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := readDate(bytes.NewBuffer(b.Bytes()), owidVersion1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Equal(e) == false {
		t.Errorf("expected date '%v', found '%v'", e, r)
	}
}

func testIoTimeMinute(t *testing.T, v byte) {
	d := time.Date(2021, time.Month(3), 4, 15, 30, 0, 0, time.UTC)
	var b bytes.Buffer
	err := writeDate(&b, d, v)
	if err != nil {
		t.Fatal(err)
	}
	r, err := readDate(bytes.NewBuffer(b.Bytes()), v)
	if err != nil {
		t.Fatal(err)
	}
	if r.Equal(d) == false {
		t.Errorf("expected date '%v', found '%v'", d, r)
	}
	if r.Minute() != d.Minute() {
		t.Errorf("Minute %d != %d", r.Minute(), d.Minute())
	}
	if r.Hour() != d.Hour() {
		t.Errorf("Hour %d != %d", r.Hour(), d.Hour())
	}
}

func testCompareDate(t *testing.T, a time.Time, b time.Time) {
	if a.Year() != b.Year() {
		fmt.Printf("Year %d != %d", a.Year(), b.Year())
		t.Fail()
	}
	if a.Month() != b.Month() {
		fmt.Printf("Month %d != %d", a.Month(), b.Month())
		t.Fail()
	}
	if a.Day() != b.Day() {
		fmt.Printf("Day %d != %d", a.Day(), b.Day())
		t.Fail()
	}
}
