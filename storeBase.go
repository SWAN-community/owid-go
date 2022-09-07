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
	"sync"
)

// storeBase is a partial implementation of owid.Store for use with other more
// complex implementations, and the test methods.
type storeBase struct {
	signers map[string]*Signer // Map of domain names to signers
	mutex   *sync.Mutex        // mutual-exclusion lock used for refresh
}

func (s *storeBase) init() {
	s.signers = make(map[string]*Signer)
	s.mutex = &sync.Mutex{}
}

// GetSigners returns a map of all the known signers keyed on domain.
func (s *storeBase) GetSigners() map[string]*Signer {
	return s.signers
}

// getSigner takes a domain name and returns the associated Signer. If a
// Signer does not exist then nil is returned.
func (s *storeBase) getSigner(domain string) (*Signer, error) {
	return s.signers[domain], nil
}
