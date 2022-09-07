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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"testing"
)

// TestOWIDSerialize checks that an OWID can be serialized and deserialized
// using standard Go methods.
func TestOWIDSerialize(t *testing.T) {
	s, o := testOWIDCreateAndVerify(t)
	t.Run("json", func(t *testing.T) {
		b, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		var a OWID
		err = json.Unmarshal(b, &a)
		if err != nil {
			t.Fatal(err)
		}
		testOWIDValidateDeserialized(t, s, &a)
	})
	t.Run("binary", func(t *testing.T) {
		var b bytes.Buffer
		err := gob.NewEncoder(&b).Encode(o)
		if err != nil {
			t.Fatal(err)
		}
		var a OWID
		err = gob.NewDecoder(&b).Decode(&a)
		if err != nil {
			t.Fatal(err)
		}
		testOWIDValidateDeserialized(t, s, &a)
	})
}

func TestOWIDVerify(t *testing.T) {
	testOWIDCreateAndVerify(t)
}

func TestOWIDBase64(t *testing.T) {
	_, o := testOWIDCreateAndVerify(t)
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromBase64(a, testByteArray)
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(b) == false {
		t.Fatal("encode and decode failed")
	}
}

func TestOWIDString(t *testing.T) {
	_, o := testOWIDCreateAndVerify(t)
	err := o.Validate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromBase64(o.AsString(), testByteArray)
	if err != nil {
		t.Fatal(err)
	}
	err = b.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if o.compare(b) == false {
		t.Fatal("encode and decode failed")
	}
}

func TestOWIDBase64CorruptShort(t *testing.T) {
	_, o := testOWIDCreateAndVerify(t)
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromBase64(a[:len(a)-1], testByteArray)
	if err == nil {
		t.Fatal("corrupt base 64 string should result in error")
	}
}

func TestOWIDBase64CorruptMiss(t *testing.T) {
	_, o := testOWIDCreateAndVerify(t)
	a, err := o.AsBase64()
	if err != nil {
		t.Fatal(err)
	}
	_, err = FromBase64(a[1:], testByteArray)
	if err == nil {
		t.Fatal("corrupt base 64 string should result in error")
	}
}

func TestOWIDByteArrayCorruptReplace(t *testing.T) {
	s, o := testOWIDCreateAndVerify(t)
	a, err := o.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	for i < len(a) {
		err = testOWIDCorrupt(s, a, i)
		if err == nil {
			t.Fatal("corrupt byte array should result in error")
		}
		i++
	}
}

// testOWIDCreateAndVerify create the OWID and verify it before returning it.
func testOWIDCreateAndVerify(t *testing.T) (*Signer, *OWID) {
	s := NewTestDefaultSigner(t)
	o, err := s.CreateOWIDandSign(testByteArray)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if v != true {
		t.Fatal("OWID did not pass verification")
	}
	return s, o
}

// Corrupt the test byte array provided at the character position and then
// verify the data with the signer returning the error.
func testOWIDCorrupt(signer *Signer, signature []byte, position int) error {
	signature[position] = signature[position] + 1
	n, err := FromByteArray(signature, testByteArray)
	if err != nil {
		return err
	}
	c, err := signer.currentKeys()
	if err != nil {
		return err
	}
	r, err := n.VerifyWithPublicKey(c.PublicKey)
	if err != nil {
		return err
	}
	if r {
		return fmt.Errorf("corrupt signature should not pass verification")
	}
	return nil
}

func testOWIDValidateDeserialized(t *testing.T, s *Signer, o *OWID) {
	err := o.Validate()
	if err != nil {
		t.Fatal(err)
	}
	o.Target = testByteArray
	v, err := s.Verify(o)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("OWID should pass verification after deserialization")
	}
}
