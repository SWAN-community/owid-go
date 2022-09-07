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

import "fmt"

// Valid OWID version formats.
const (
	owidEmpty      byte = 0 // Used for writing empty OWID markers
	owidVersion1   byte = 1
	owidVersionMax byte = 1
)

// The OWID versions that are supported.
var owidVersions = []byte{owidVersion1}

// The minimum length of the organization name for the signer
const minNameLength = 5

// The maximum length of the organization name for the signer
const maxNameLength = 40

// The maximum length of the terms URL for the signer
const maxTermsURLLength = 250

// Message to display if the maximum terms are too long
var termsLengthMessage = fmt.Sprintf("Terms URL maximum length %d", maxTermsURLLength)

// Message to display if the name of the signer is too long or too short
var nameLengthMessage = fmt.Sprintf("Name must be between %d and %d characters", minNameLength, maxNameLength)

// Message to display if an invalid URL is provided
var termsInvalidMessage = "Terms URL is invalid"

// The maximum length of an OWID signature in bytes.
const signatureLength = 64

// Half the maximum length of an OWID signature in bytes.
const halfSignatureLength = signatureLength / 2

// Constants used for the storing of keys for signing, domains and organization
// information. Used in AWS, Azure, and GCP.
// cspell:ignore owidsigners owidkeys
const (
	signersTableName             = "owidsigners"
	signersTablePartitionKeyName = "OwidSigner"
	signersTableDomainAttribute  = "Domain"
	signersTablePartitionKey     = "signers"
	keysTableName                = "owidkeys"
	keysTablePartitionKeyName    = "Domain"
	domainFieldName              = "domain"
	publicKeyFieldName           = "publicKey"
	privateKeyFieldName          = "privateKey"
	nameFieldName                = "name"
	contractURLFieldName         = "contractURL"
	createdFieldName             = "created"
)
