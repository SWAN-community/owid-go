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
	"container/list"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const (
	owidVersion = 1
)

// OWID structure which can be used as a node in a tree.
type OWID struct {
	Version   byte      `json:"version"`   // The byte version of the OWID. Version 1 only.
	Domain    string    `json:"domain"`    // Domain associated with the creator.
	Signature []byte    `json:"signature"` // Signature for this OWID and it's ancestor from the creator.
	Date      time.Time `json:"date"`      // The date and time to the nearest minute in UTC of the creation.
	Payload   []byte    `json:"payload"`   // Array of bytes that form the identifier.
	Children  []*OWID   `json:"children"`  // The children of this OWID if part of a tree.
	parent    *OWID     // The parent of this OWID if part of a tree.
}

// GetIndex returns the index for this OWID in the tree.
func (o *OWID) GetIndex() []uint32 {
	var i []uint32
	p := o.parent
	for p != nil {
		var a int
		var b *OWID
		for a, b = range p.Children {
			if b == o {
				break
			}
		}
		i = append([]uint32{uint32(a)}, i...)
		o = p
		p = p.parent
	}
	return i
}

// GetIndexAsString returns the index for this OWID in the tree as a comma
// separated string.
func (o *OWID) GetIndexAsString() string {
	b := make([]byte, 0, 128)
	i := o.GetIndex()
	if len(i) > 0 {
		for _, n := range i {
			b = strconv.AppendInt(b, int64(n), 10)
			b = append(b, ',')
		}
		return string(b[:len(b)-1])
	}
	return ""
}

// GetRoot returns the OWID at the root of the tree.
func (o *OWID) GetRoot() *OWID {
	p := o
	r := o
	for p != nil {
		r = p
		p = p.parent
	}
	return r
}

// GetParent returns the immediate parent of this OWID.
func (o *OWID) GetParent() *OWID { return o.parent }

// PayloadAsString converts the payload to a string.
func (o *OWID) PayloadAsString() string {
	return string(o.Payload)
}

// PayloadAsPrintable returns a string representation of the payload.
func (o *OWID) PayloadAsPrintable() string {
	return fmt.Sprintf("%x ", o.Payload)
}

// PayloadAsBase64 returns the payload as a URL encoded base 64 string.
func (o *OWID) PayloadAsBase64() string {
	return base64.URLEncoding.EncodeToString(o.Payload)
}

// NewOwid creates a new unsigned instance of the OWID structure.
func NewOwid(
	domain string,
	date time.Time,
	payload []byte) (*OWID, error) {
	var o OWID
	o.Version = owidVersion
	o.Domain = domain
	o.Date = date
	o.Payload = payload
	return &o, nil
}

// Find the first ID that matches the condition.
func (o *OWID) Find(condition func(n *OWID) bool) *OWID {
	q := list.New()
	q.PushBack(o)
	for q.Len() > 0 {
		o := dequeue(q)
		if condition(o) {
			return o
		}
		i := 0
		for i < len(o.Children) {
			q.PushBack(o.Children[i])
			i = i + 1
		}
	}
	return nil
}

// AddChild adds the OWID to the children of this OWID returning the index of
// the child.
func (o *OWID) AddChild(child *OWID) (uint32, error) {
	if child == nil {
		return uint32(0), fmt.Errorf("child must for a valid array")
	}
	if child.parent != nil {
		return uint32(0), fmt.Errorf("child already associated with a parent")
	}
	o.Children = append(o.Children, child)
	child.parent = o
	return uint32(len(o.Children) - 1), nil
}

// AddChildren includes the other Ids provided in the list of children for this
// Id.
func (o *OWID) AddChildren(children []*OWID) error {
	if children == nil {
		return fmt.Errorf("children must for a valid array")
	}
	for _, c := range children {
		_, err := o.AddChild(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetLeaf returns the single leaf if only a single leaf exists, otherwise an
// error is returned.
func (o *OWID) GetLeaf() (*OWID, error) {
	for o.Children != nil && len(o.Children) == 1 {
		o = o.Children[0]
	}
	if len(o.Children) > 1 {
		return nil, fmt.Errorf("Tree contains multiple leaves")
	}
	return o, nil
}

// GetOWID returns the node at the integer indexes provided where each index of
// the array o is the level of the tree. To find the third, fourth and then
// second child of a tree the array could contain { 2, 3, 1 }.
func (o *OWID) GetOWID(index []uint32) (*OWID, error) {
	if index == nil {
		return nil, fmt.Errorf("index must no be nil")
	}
	l := 0
	c := o
	for l < len(index) {
		if len(c.Children) == 0 {
			return nil, fmt.Errorf("OWID not found")
		}
		if index[l] >= uint32(len(c.Children)) {
			return nil, fmt.Errorf("OWID not found")
		}
		c = c.Children[index[l]]
		l = l + 1
	}
	return c, nil
}

// Sign this OWID and it's ancestors using the Crypto instance provided.
func (o *OWID) Sign(c *Crypto) error {
	b, err := o.dataForCrypto()
	if err != nil {
		return err
	}
	o.Signature, err = c.SignByteArray(b)
	if err != nil {
		return err
	}
	return nil
}

// VerifyWithCrypto this OWID and it's ancestors using the Crypto instance
// provided.
func (o *OWID) VerifyWithCrypto(c *Crypto) (bool, error) {
	b, err := o.dataForCrypto()
	if err != nil {
		return false, err
	}
	return c.VerifyByteArray(b, o.Signature)
}

// VerifyWithPublicKey this OWID and it's ancestors using the public key in PEM
// format provided.
func (o *OWID) VerifyWithPublicKey(public string) (bool, error) {
	c, err := NewCryptoVerifyOnly(public)
	if err != nil {
		return false, err
	}
	return o.VerifyWithCrypto(c)
}

// Verify this OWID and it's ancestors by fetching the public key from the
// domain associated with the OWID.
func (o *OWID) Verify(scheme string) (bool, error) {
	r, err := http.Get(fmt.Sprintf(
		"%s://%s/owid/api/v%d/public-key?format=pkcs",
		scheme,
		o.Domain,
		o.Version))
	if err != nil {
		return false, err
	}
	if r.StatusCode != http.StatusOK {
		return false, fmt.Errorf(
			"Domain '%s' return code '%d'",
			o.Domain,
			r.StatusCode)
	}
	v, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return false, err
	}
	return o.VerifyWithPublicKey(string(v))
}

// TreeAsJSON returns the OWID and it's descendents as a JSON string.
func (o *OWID) TreeAsJSON() (string, error) {
	j, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return string(j), err
}

// TreeToBuffer appends the OWID tree to the buffer provided.
func (o *OWID) TreeToBuffer(f *bytes.Buffer) error {
	q := list.New()
	q.PushBack(o)
	for q.Len() > 0 {
		o := dequeue(q)
		err := o.toBuffer(f)
		if err != nil {
			return err
		}
		i := 0
		for i < len(o.Children) {
			q.PushBack(o.Children[i])
			i = i + 1
		}
	}
	return nil
}

// TreeAsByteArray returns the OWID and it's descendents as a byte array.
func (o *OWID) TreeAsByteArray() ([]byte, error) {
	var f bytes.Buffer
	err := o.TreeToBuffer(&f)
	if err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// TreeAsBase64 returns the OWID and it's descendents as a base64 string.
func (o *OWID) TreeAsBase64() (string, error) {
	b, err := o.TreeAsByteArray()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// TreeAsString returns the OWID and it's descendents as a base64 string or the
// text of any error message.
func (o *OWID) TreeAsString() string {
	s, err := o.TreeAsBase64()
	if err != nil {
		return err.Error()
	}
	return s
}

// ToBuffer appends the single OWID to the buffer provided.
func (o *OWID) ToBuffer(f *bytes.Buffer) error {
	return o.toBufferNoChildren(f)
}

// AsByteArray returns the single OWID as a byte array.
func (o *OWID) AsByteArray() ([]byte, error) {
	var f bytes.Buffer
	err := o.ToBuffer(&f)
	if err != nil {
		return nil, err
	}
	return f.Bytes(), nil
}

// AsBase64 returns the single OWID as a base 64 string.
func (o *OWID) AsBase64() (string, error) {
	b, err := o.AsByteArray()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// AsString returns the single OWID as a base 64 string or the text of any error
// message.
func (o *OWID) AsString() string {
	s, err := o.AsBase64()
	if err != nil {
		return err.Error()
	}
	return s
}

// TreeFromJSON creates an OWID tree from the JSON byte array.
func TreeFromJSON(j string) (*OWID, error) {
	var o OWID
	err := json.Unmarshal([]byte(j), &o)
	if err != nil {
		return nil, err
	}
	o.SetParents()
	return &o, nil
}

// TreeFromBuffer creates an OWID tree from the buffer provided.
func TreeFromBuffer(b *bytes.Buffer) (*OWID, error) {
	q := list.New()
	r, err := fromBuffer(b)
	if err != nil {
		return nil, err
	}
	q.PushBack(r)
	for q.Len() > 0 {
		o := dequeue(q)
		i := 0
		for i < cap(o.Children) {
			o.Children[i], err = fromBuffer(b)
			if err != nil {
				return nil, err
			}
			o.Children[i].parent = o
			q.PushBack(o.Children[i])
			i = i + 1
		}
	}
	return r, nil
}

// TreeFromByteArray creates an OWID tree from the byte array.
func TreeFromByteArray(b []byte) (*OWID, error) {
	return TreeFromBuffer(bytes.NewBuffer(b))
}

// TreeFromBase64 creates an OWID tree from the base 64 string.
func TreeFromBase64(value string) (*OWID, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return TreeFromByteArray(b)
}

// FromBuffer creates a single OWID from the buffer.
func FromBuffer(b *bytes.Buffer) (*OWID, error) {
	return fromBuffer(b)
}

// FromByteArray creates a single OWID from the byte array.
func FromByteArray(b []byte) (*OWID, error) {
	return FromBuffer(bytes.NewBuffer(b))
}

// FromBase64 creates a single OWID from the base 64 string.
func FromBase64(value string) (*OWID, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return FromByteArray(b)
}

// SetParents the parent pointer for the children ready for subsequent
// operations. Used when the tree of OWIDs is created from JSON.
func (o *OWID) SetParents() {
	q := list.New()
	q.PushBack(o)
	for q.Len() > 0 {
		o := dequeue(q)
		i := 0
		for i < len(o.Children) {
			o.Children[i].parent = o
			q.PushBack(o.Children[i])
			i = i + 1
		}
	}
}

// dataForCrypto adds the fields from this OWID to the byte buffer without
// the signature or the number of children. Adds the root OWID data including
// the signature.
func (o *OWID) dataForCrypto() ([]byte, error) {
	var f bytes.Buffer
	o.toBufferNoSignatureOrChildren(&f)
	r := o.GetRoot()
	if r != nil && r != o {
		r.toBufferNoChildren(&f)
	}
	return f.Bytes(), nil
}

func dequeue(q *list.List) *OWID {
	e := q.Front()
	q.Remove(e)
	return e.Value.(*OWID)
}

func fromBuffer(b *bytes.Buffer) (*OWID, error) {
	var o OWID
	var err error
	o.Version, err = readByte(b)
	if err != nil {
		return nil, err
	}
	switch o.Version {
	case 1:
		fromBufferV1(b, &o)
		break
	default:
		return nil, fmt.Errorf("Version '%d' not supported", o.Version)
	}
	return &o, nil
}

func fromBufferV1(b *bytes.Buffer, o *OWID) error {
	var err error
	o.Domain, err = readString(b)
	if err != nil {
		return err
	}
	o.Date, err = readDate(b)
	if err != nil {
		return err
	}
	o.Payload, err = readByteArray(b)
	if err != nil {
		return err
	}
	o.Signature, err = readByteArray(b)
	if err != nil {
		return err
	}
	l, err := readUint32(b)
	if err != nil {
		return err
	}
	o.Children = make([]*OWID, l)
	return nil
}

func (o *OWID) toBuffer(b *bytes.Buffer) error {
	err := o.toBufferNoChildren(b)
	if err != nil {
		return err
	}
	err = writeUint32(b, uint32(len(o.Children)))
	if err != nil {
		return err
	}
	return nil
}

func (o *OWID) toBufferNoChildren(b *bytes.Buffer) error {
	err := o.toBufferNoSignatureOrChildren(b)
	if err != nil {
		return err
	}
	err = writeByteArray(b, o.Signature)
	if err != nil {
		return err
	}
	return nil
}

func (o *OWID) toBufferNoSignatureOrChildren(b *bytes.Buffer) error {
	err := writeByte(b, o.Version)
	if err != nil {
		return err
	}
	err = writeString(b, o.Domain)
	if err != nil {
		return err
	}
	err = writeDate(b, o.Date)
	if err != nil {
		return err
	}
	err = writeByteArray(b, o.Payload)
	if err != nil {
		return err
	}
	return nil
}
