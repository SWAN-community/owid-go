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

// Interface used for the storing of keys for signing, domains and organization
// information. Implemented in Azure and AWS.

const (
	creatorsTableName             = "owidcreators"
	creatorsTablePartitionKeyName = "Owidcreator"
	creatorsTableDomainAttribute  = "Domain"
	creatorsTablePartitionKey     = "creator"
	domainFieldName               = "domain"
	publicKeyFieldName            = "publicKey"
	privateKeyFieldName           = "privateKey"
	nameFieldName                 = "name"
	contractURLFieldName          = "contractURL"
)

// Store is an interface for accessing persistent data.
type Store interface {

	// GetCreator returns the creator information for the domain.
	GetCreator(domain string) (*Creator, error)

	// GetCreators return a map of all the known creators keyed on domain.
	GetCreators() map[string]*Creator

	// setCreator inserts a new creator.
	setCreator(c *Creator) error
}

// NewStore returns a work implementation of the Store interface for the
// configuration supplied.
func NewStore(c Configuration) Store {
	var owidStore Store
	var err error

	if (len(c.AzureStorageAccount) > 0 || len(c.AzureStorageAccessKey) > 0) &&
		(c.OwidStore == "" || c.OwidStore == "azure") {
		if len(c.AzureStorageAccount) == 0 || len(c.AzureStorageAccessKey) == 0 {
			panic(errors.New("Either the AZURE_STORAGE_ACCOUNT or " +
				"AZURE_STORAGE_ACCESS_KEY environment variable is not set"))
		}
		log.Printf("OWID:Using Azure Table Storage")
		owidStore, err = NewAzure(
			c.AzureStorageAccount,
			c.AzureStorageAccessKey)
		if err != nil {
			panic(err)
		}
	} else if len(c.GcpProject) > 0 &&
		(c.OwidStore == "" || c.OwidStore == "gcp") {
		log.Printf("OWID:Using Google Firebase")
		owidStore, err = NewFirebase(c.GcpProject)
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
		panic(fmt.Errorf("OWID:no store has been configured.\r\n" +
			"Provide details for store by specifying one or more sets of " +
			"environment variables:\r\n" +
			"(1) Azure Storage account details 'AZURE_STORAGE_ACCOUNT' & 'AZURE_STORAGE_ACCESS_KEY'\r\n" +
			"(2) GCP project in 'GCP_PROJECT' \r\n" +
			"(3) Local storage file paths in 'OWID_FILE'\r\n" +
			"(4) AWS Dynamo DB by setting 'AWS_ENABLED' to true\r\n" +
			"Refer to https://github.com/SWAN-community/owid-go/blob/main/README.md " +
			"for specifics on setting up each storage solution"))
	} else if c.Debug {

		// If in debug more log the nodes at startup.
		for _, o := range owidStore.GetCreators() {
			log.Println(fmt.Sprintf("OWID:\t%s", o.Domain()))
		}
	}

	return owidStore
}
