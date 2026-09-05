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
	"os"
	"strings"
	"testing"
)

// modulePath is the one import path this module has, which every consumer
// requires it by whichever copy of the repository they read the source from.
const modulePath = "github.com/SWAN-community/owid-go"

// TestModulePathIsTheDocumentedOne holds go.mod and the README together.
//
// A copy of this repository is published at github.com/51Degrees/owid-go and
// declares this same path, because a mirror of a module is not a second
// module. A consumer that required the mirror path was told:
//
//	module declares its path as: github.com/SWAN-community/owid-go
//	        but was required as: github.com/51Degrees/owid-go
//
// The answer is to require the path below, not to change it, since changing
// it would break every consumer that already requires it. The README says so
// and this test fails if the two ever disagree.
func TestModulePathIsTheDocumentedOne(t *testing.T) {
	b, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := "module " + modulePath
	first := strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]
	if strings.TrimSpace(first) != want {
		t.Errorf("expected go.mod to start %q, got %q", want, first)
	}

	r, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(r)
	for _, s := range []string{
		"go get " + modulePath,
		modulePath + "` is the only import path",
		"github.com/51Degrees/owid-go",
	} {
		if !strings.Contains(readme, s) {
			t.Errorf("the README should say %q", s)
		}
	}
}
