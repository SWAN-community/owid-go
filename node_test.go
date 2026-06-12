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
)

// newTestTree creates a tree with a root and a chain of two child nodes. The
// nodes are returned in order from the root to the leaf.
func newTestTree(t *testing.T) (*Node, *Node, *Node) {
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	root := &Node{}
	o, err := c.CreateOWIDandSign([]byte("root"))
	if err != nil {
		t.Fatal(err)
	}
	root.OWID, err = o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	o1, err := c.CreateOWIDandSign([]byte("child"))
	if err != nil {
		t.Fatal(err)
	}
	c1, err := root.AddOWID(o1)
	if err != nil {
		t.Fatal(err)
	}
	o2, err := c.CreateOWIDandSign([]byte("grandchild"))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := c1.AddOWID(o2)
	if err != nil {
		t.Fatal(err)
	}
	return root, c1, c2
}

// TestNodeTree verifies the relationships in a small tree of OWID nodes.
func TestNodeTree(t *testing.T) {
	root, c1, c2 := newTestTree(t)
	if c2.GetRoot() != root {
		t.Error("leaf did not return the root of the tree")
	}
	if root.GetParent() != nil {
		t.Error("root should not have a parent")
	}
	if c1.GetParent() != root {
		t.Error("child did not return the root as parent")
	}
	if c2.GetParent() != c1 {
		t.Error("grandchild did not return the child as parent")
	}
	l, err := root.GetLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if l != c2 {
		t.Error("leaf of the tree should be the grandchild")
	}
	i := c2.GetIndex()
	if len(i) != 2 || i[0] != 0 || i[1] != 0 {
		t.Errorf("expected index '[0 0]', found '%v'", i)
	}
	if c2.GetIndexAsString() != "0,0" {
		t.Errorf("expected index '0,0', found '%s'", c2.GetIndexAsString())
	}
}

// TestNodeAddChild verifies that adding a second child changes the index and
// node retrieval results, and that a single leaf no longer exists.
func TestNodeAddChild(t *testing.T) {
	root, c1, _ := newTestTree(t)
	c, err := newTestCreator(testDomain, testOrgName, registerContractURL)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.CreateOWIDandSign([]byte("extra"))
	if err != nil {
		t.Fatal(err)
	}
	var extra Node
	extra.OWID, err = o.AsByteArray()
	if err != nil {
		t.Fatal(err)
	}
	x, err := c1.AddChild(&extra)
	if err != nil {
		t.Fatal(err)
	}
	if x != 1 {
		t.Errorf("expected child index '1', found '%d'", x)
	}
	if extra.GetIndexAsString() != "0,1" {
		t.Errorf("expected index '0,1', found '%s'", extra.GetIndexAsString())
	}
	n, err := root.GetNode([]uint32{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if n != &extra {
		t.Error("GetNode did not return the added child")
	}
	_, err = root.GetLeaf()
	if err == nil {
		t.Fatal(fmt.Errorf("multiple leaves should result in error"))
	}
}

// TestNodeJSON verifies that a tree serialized with AsJSON can be recreated
// with NodeFromJSON and that the parents are set in the new tree.
func TestNodeJSON(t *testing.T) {
	root, _, c2 := newTestTree(t)
	j, err := root.AsJSON()
	if err != nil {
		t.Fatal(err)
	}
	n, err := NodeFromJSON(j)
	if err != nil {
		t.Fatal(err)
	}
	l, err := n.GetLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if l.GetRoot() != n {
		t.Error("parents not set after NodeFromJSON")
	}
	if l.GetIndexAsString() != "0,0" {
		t.Errorf("expected index '0,0', found '%s'", l.GetIndexAsString())
	}
	a, err := l.GetOWID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := c2.GetOWID()
	if err != nil {
		t.Fatal(err)
	}
	if a.compare(b) == false {
		t.Error("leaf OWID does not match after JSON round trip")
	}
}
