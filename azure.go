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
	"time"

	"github.com/Azure/azure-sdk-for-go/storage"
)

const (
	azureTimeout = 2
)

// Azure is a concrete implementation of store.go, connecting to Azure table
// storage
type Azure struct {
	timestamp     time.Time      // The last time the maps were refreshed
	creatorsTable *storage.Table // Reference to the creator table
	common
}

// NewAzure creates a new instance of the Azure structure.
func NewAzure(account string, accessKey string) (*Azure, error) {
	var a Azure
	c, err := storage.NewBasicClient(account, accessKey)
	if err != nil {
		return nil, err
	}
	ts := c.GetTableService()
	a.mutex = &sync.Mutex{}
	a.creatorsTable = ts.GetTableReference(creatorsTableName)
	err = azureCreateTable(a.creatorsTable)
	if err != nil {
		return nil, err
	}
	err = a.refresh()
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetCreator gets creator for domain from internal map, updating the internal
// map if the creator is not in the map.
func (a *Azure) GetCreator(domain string) (*Creator, error) {
	c, err := a.common.getCreator(domain)
	if err != nil {
		return nil, err
	}
	if c == nil {
		err = a.refresh()
		if err != nil {
			return nil, err
		}
		c, err = a.common.getCreator(domain)
	}
	return c, err
}

func (a *Azure) setCreator(creator *Creator) error {
	e := a.creatorsTable.GetEntityReference(creatorsTablePartitionKey, creator.domain)
	e.Properties = make(map[string]interface{})
	e.Properties[privateKeyFieldName] = creator.privateKey
	e.Properties[publicKeyFieldName] = creator.publicKey
	e.Properties[nameFieldName] = creator.name
	return e.Insert(storage.FullMetadata, nil)
}

func azureCreateTable(t *storage.Table) error {
	err := t.Create(azureTimeout, storage.FullMetadata, nil)
	if err != nil {
		switch e := err.(type) {
		case storage.AzureStorageServiceError:
			if e.Code != "TableAlreadyExists" {
				return err
			}
		default:
			return err
		}
	}
	return nil
}

func (a *Azure) refresh() error {
	// Fetch the creators
	cs, err := a.fetchCreators()
	if err != nil {
		return err
	}
	// In a single atomic operation update the reference to the creators.
	a.mutex.Lock()
	a.creators = cs
	a.mutex.Unlock()

	return nil
}

func (a *Azure) fetchCreators() (map[string]*Creator, error) {
	var err error
	cs := make(map[string]*Creator)

	// Fetch all the records from the nodes table in Azure.
	e, err := a.creatorsTable.QueryEntities(
		azureTimeout,
		storage.FullMetadata,
		nil)
	if err != nil {
		return nil, err
	}

	// Iterate over the records creating nodes and adding them to the creators
	// map.
	for _, i := range e.Entities {
		cs[i.RowKey], err = newCreator(
			i.RowKey,
			i.Properties[privateKeyFieldName].(string),
			i.Properties[publicKeyFieldName].(string),
			i.Properties[nameFieldName].(string))
		if err != nil {
			return nil, err
		}
	}

	return cs, err
}
