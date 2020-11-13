/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited
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

// Creator of Open Web Ids and immutable data.
type creator struct {
	domain     string // The registered domain name and key fields
	privateKey string
	publicKey  string
	name       string // The name of the entity associated with the domain
}

func (c *creator) Domain() string { return c.domain }

func newCreator(
	domain string,
	privateKey string,
	publicKey string,
	name string) (*creator, error) {
	c := creator{
		domain,
		privateKey,
		publicKey,
		name}
	return &c, nil
}
