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

// storeTest used to support OWID tests. All the signers data is held in memory
// and not persisted.
type storeTest struct {
	storeBase
}

// newTestStore creates a new test store and adds the domain swan.community
// as an OWID signer.
func newTestStore() *storeTest {
	var st storeTest
	st.init()
	return &st
}

func (st *storeTest) GetSigner(domain string) (*Signer, error) {
	return st.getSigner(domain)
}

func (st *storeTest) refresh() error {
	// Do nothing.
	return nil
}

func (st *storeTest) addSigner(s *Signer) error {
	st.signers[s.Domain] = s
	return nil
}

func (st *storeTest) addKeys(d string, k *Keys) error {
	st.signers[d].Keys = append(st.signers[d].Keys, k)
	return nil
}
