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
	"log"
	"os"
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
)

// Store is an interface for accessing persistent data.
type Store interface {

	// GetCreator returns the creator information for the domain.
	GetCreator(domain string) (*Creator, error)

	// setCreator inserts a new creator.
	setCreator(c *Creator) error
}

// NewStore returns a work implementation of the Store interface for the
// configuration supplied.
func NewStore(owidConfig Configuration) Store {
	var owidStore Store
	var err error

	azureAccountName, azureAccountKey, gcpProject, owidFile, awsEnabled, os :=
		os.Getenv("AZURE_STORAGE_ACCOUNT"),
		os.Getenv("AZURE_STORAGE_ACCESS_KEY"),
		os.Getenv("GCP_PROJECT"),
		os.Getenv("OWID_FILE"),
		os.Getenv("AWS_ENABLED"),
		os.Getenv("OWID_STORE")
	if (len(azureAccountName) > 0 || len(azureAccountKey) > 0) &&
		(os == "" || os == "azure") {
		if len(azureAccountName) == 0 || len(azureAccountKey) == 0 {
			panic(errors.New("Either the AZURE_STORAGE_ACCOUNT or " +
				"AZURE_STORAGE_ACCESS_KEY environment variable is not set"))
		}
		log.Printf("OWID: Using Azure Table Storage")
		owidStore, err = NewAzure(
			azureAccountName,
			azureAccountKey)
		if err != nil {
			panic(err)
		}
	} else if len(gcpProject) > 0 && (os == "" || os == "gcp") {
		log.Printf("OWID: Using Google Firebase")
		owidStore, err = NewFirebase(gcpProject)
		if err != nil {
			panic(err)
		}
	} else if len(owidFile) > 0 && (os == "" || os == "local") {
		log.Printf("OWID: Using local storage")
		owidStore, err = NewLocalStore(owidFile)
		if err != nil {
			panic(err)
		}
	} else if len(awsEnabled) > 0 && (os == "" || os == "aws") {
		log.Printf("OWID: Using AWS DynamoDB")
		owidStore, err = NewAWS()
		if err != nil {
			panic(err)
		}
	}

	if owidStore == nil {
		panic(errors.New("owid store not configured"))
	}

	return owidStore
}
