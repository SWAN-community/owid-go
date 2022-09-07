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
	"github.com/SWAN-community/access-go"
)

// Services references all the information needed for OWID methods.
type Services struct {
	config *Configuration // Configuration used by the server.
	store  Store          // Instance of storage service for signer data
	access access.Access  // Instance of access service used to verify additions of keys for existing signers.
}

// NewServices a set of services to use with OWID. These provide defaults via
// the configuration parameter, and access to persistent storage for signer
// configuration via the store parameter.
// config
func NewServices(config *Configuration, store Store, access access.Access) *Services {
	return &Services{config: config, store: store, access: access}
}

// GetSigner returns the signer from the store used by the service.
func (s *Services) GetSigner(host string) (*Signer, error) {
	return s.store.GetSigner(host)
}
