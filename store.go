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
	"errors"
	"fmt"
	"log"
)

// Store is an interface for accessing persistent signer data for signing and
// verifying OWIDs.
type Store interface {

	// GetSigner returns the signer information for the domain.
	GetSigner(domain string) (*Signer, error)

	// GetSigners return a map of all the known signers keyed on domain.
	GetSigners() map[string]*Signer

	// addSigner inserts a new signer.
	addSigner(signer *Signer) error

	// addKeys inserts a new key for the domain.
	addKeys(domain string, key *Keys) error

	// refresh the in memory cache of the permanent store.
	refresh() error
}

// NewStore returns a work implementation of the Store interface for the
// configuration supplied.
func NewStore(c *Configuration) Store {
	var owidStore Store
	var err error

	if (len(c.AzureStorageAccount) > 0 || len(c.AzureStorageAccessKey) > 0) &&
		(c.OwidStore == "" || c.OwidStore == "azure") {
		if len(c.AzureStorageAccount) == 0 || len(c.AzureStorageAccessKey) == 0 {
			panic(errors.New("either the AZURE_STORAGE_ACCOUNT or " +
				"AZURE_STORAGE_ACCESS_KEY environment variable is not set"))
		}
		log.Printf("OWID:Using Azure Table Storage")
		// TODO: Reimplement Azure storage with multiple keys
		// owidStore, err = NewAzure(
		// 	c.AzureStorageAccount,
		// 	c.AzureStorageAccessKey)
		if err != nil {
			panic(err)
		}
	} else if len(c.GcpProject) > 0 &&
		(c.OwidStore == "" || c.OwidStore == "gcp") {
		log.Printf("OWID:Using Google Firebase")
		// TODO: Reimplement GCP storage with multiple keys
		// owidStore, err = NewFirebase(c.GcpProject)
		if err != nil {
			panic(err)
		}
	} else if len(c.OwidFile) > 0 &&
		(c.OwidStore == "" || c.OwidStore == "local") {
		log.Printf("OWID:Using local storage")
		owidStore, err = NewLocalStore(c.OwidFile)
		if err != nil {
			panic(err)
		}
	} else if c.AwsEnabled &&
		(c.OwidStore == "" || c.OwidStore == "aws") {
		log.Printf("OWID:Using AWS DynamoDB")
		owidStore, err = NewAWS()
		if err != nil {
			panic(err)
		}
	}

	if owidStore == nil {
		panic(fmt.Errorf("OWID:no store has been configured.\n" +
			"Provide details for store by specifying one or more sets of " +
			"environment variables:\n" +
			"(1) Azure Storage account details 'AZURE_STORAGE_ACCOUNT' & 'AZURE_STORAGE_ACCESS_KEY'\n" +
			"(2) GCP project in 'GCP_PROJECT' \n" +
			"(3) Local storage file paths in 'OWID_FILE'\n" +
			"(4) AWS Dynamo DB by setting 'AWS_ENABLED' to true\n" +
			"Refer to https://github.com/SWAN-community/owid-go/blob/main/README.md " +
			"for specifics on setting up each storage solution"))
	} else if c.Debug {

		// If in debug more log the domains at startup.
		for _, o := range owidStore.GetSigners() {
			log.Printf("OWID:\t%s\n", o.Domain)
		}
	}

	return owidStore
}
