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
	"container/list"
	"encoding/json"
	"fmt"
	"strconv"
)

// Node in a tree of nodes.
type Node struct {
	OWID     []byte      // The OWID byte array
	Children []*Node     // The children of this node, or nil if a leaf
	Value    interface{} // The value associated with the OWID node
	parent   *Node       // The parent of this node, or nil if the root
}

// GetParent returns the parent for this node.
func (n *Node) GetParent() *Node {
	return n.parent
}

// GetOWID returns the OWID associated with the node.
func (n *Node) GetOWID() (*OWID, error) {
	return FromByteArray(n.OWID)
}

// GetOWIDAsString returns the OWID as a base 64 string.
func (n *Node) GetOWIDAsString() string {
	o, err := n.GetOWID()
	if err != nil {
		return ""
	}
	return o.AsString()
}

// GetIndex returns the index for this OWID in the tree.
func (n *Node) GetIndex() []uint32 {
	var i []uint32
	p := n.parent
	for p != nil {
		var a int
		var b *Node
		for a, b = range p.Children {
			if b == n {
				break
			}
		}
		i = append([]uint32{uint32(a)}, i...)
		n = p
		p = p.parent
	}
	return i
}

// GetIndexAsString returns the index for this OWID in the tree as a comma
// separated string.
func (n *Node) GetIndexAsString() string {
	b := make([]byte, 0, 128)
	i := n.GetIndex()
	if len(i) > 0 {
		for _, n := range i {
			b = strconv.AppendInt(b, int64(n), 10)
			b = append(b, ',')
		}
		return string(b[:len(b)-1])
	}
	return ""
}

// GetRoot returns the Node at the root of the tree.
func (n *Node) GetRoot() *Node {
	p := n
	r := n
	for p != nil {
		r = p
		p = p.parent
	}
	return r
}

// Find the first Node that matches the condition.
func (n *Node) Find(condition func(n *Node) bool) *Node {
	q := list.New()
	q.PushBack(n)
	for q.Len() > 0 {
		n = dequeue(q)
		if condition(n) {
			return n
		}
		i := 0
		for i < len(n.Children) {
			q.PushBack(n.Children[i])
			i = i + 1
		}
	}
	return nil
}

// AddChild adds the child to the children of this Node returning the index of
// the child.
func (n *Node) AddChild(child *Node) (uint32, error) {
	if child == nil {
		return uint32(0), fmt.Errorf("child must for a valid array")
	}
	if child.parent != nil {
		return uint32(0), fmt.Errorf("child already associated with a parent")
	}
	n.Children = append(n.Children, child)
	child.parent = n
	return uint32(len(n.Children) - 1), nil
}

// AddOWID adds the OWID child to the children of this Node returning the new
// child node.
func (n *Node) AddOWID(o *OWID) (*Node, error) {
	var err error
	var c Node
	c.OWID, err = o.AsByteArray()
	if err != nil {
		return nil, err
	}
	_, err = n.AddChild(&c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AddChildren includes the other Nodes provided in the list of children for
// this node.
func (n *Node) AddChildren(children []*Node) error {
	if children == nil {
		return fmt.Errorf("children must for a valid array")
	}
	for _, c := range children {
		_, err := n.AddChild(c)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetLeaf returns the single leaf if only a single leaf exists, otherwise an
// error is returned.
func (n *Node) GetLeaf() (*Node, error) {
	for n.Children != nil && len(n.Children) == 1 {
		n = n.Children[0]
	}
	if len(n.Children) > 1 {
		return nil, fmt.Errorf("Tree contains multiple leaves")
	}
	return n, nil
}

// GetNode returns the node at the integer indexes provided where each index of
// the array o is the level of the tree. To find the third, fourth and then
// second child of a tree the array could contain { 2, 3, 1 }.
func (n *Node) GetNode(index []uint32) (*Node, error) {
	if index == nil {
		return nil, fmt.Errorf("index must no be nil")
	}
	l := 0
	c := n
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

// SetParents the parent pointer for the children ready for subsequent
// operations. Used when the tree of nodes is created from JSON.
func (n *Node) SetParents() {
	q := list.New()
	q.PushBack(n)
	for q.Len() > 0 {
		n = dequeue(q)
		i := 0
		for i < len(n.Children) {
			n.Children[i].parent = n
			q.PushBack(n.Children[i])
			i = i + 1
		}
	}
}

// NodeFromJSON creates a node tree from the JSON returning the root node.
func NodeFromJSON(j []byte) (*Node, error) {
	var n Node
	err := json.Unmarshal(j, &n)
	if err != nil {
		return nil, err
	}
	n.SetParents()
	return &n, nil
}

// AsJSON returns this node and all the descendents as a JSON string.
func (n *Node) AsJSON() ([]byte, error) {
	j, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	return j, err
}

func dequeue(q *list.List) *Node {
	e := q.Front()
	q.Remove(e)
	return e.Value.(*Node)
}
