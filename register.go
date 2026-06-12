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

// Register contains HTML template data used to register a creator
type Register struct {
	Services         *Services // Services used to store the new creator
	Domain           string    // Domain of the creator being registered
	Name             string    // Legal name of the creator
	ContractURL      string    // URL with the T&Cs for the creation of data
	Error            string    // General error message from the registration
	NameError        string    // Error message for the name field
	ContractURLError string    // Error message for the contract URL field
	ReadOnly         bool      // True when the registration is complete
	DisplayErrors    bool      // True when error messages should be shown
}
