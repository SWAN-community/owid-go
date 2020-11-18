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

// common is a partial implementation of sws.Store for use with other more
// complex implementations, and the test methods.
type common struct {
	creators map[string]*Creator // Map of domain names to nodes
	mutex    *sync.Mutex         // mutual-exclusion lock used for refresh
}

func (c *common) init() {
	c.creators = make(map[string]*Creator)
	c.mutex = &sync.Mutex{}
}

// GetCreator takes a domain name and returns the associated creator. If a
// creator does not exist then nil is returned.
func (c *common) getCreator(domain string) (*Creator, error) {
	return c.creators[domain], nil
}
