/* ****************************************************************************
 * Copyright 2021 51 Degrees Mobile Experts Limited (51degrees.com)
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
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

// Local store implementation for OWID - data is stored in maps in memory and
// persisted on disk using JSON files.
type Local struct {
	timestamp time.Time // The last time the maps were refreshed
	file      string    // file path
	common
}

// NewLocalStore creates a new instance of Local from a given file path.
func NewLocalStore(file string) (*Local, error) {
	var l Local

	l.file = file

	l.mutex = &sync.Mutex{}
	err := l.refresh()
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// setCreator adds a new Creator to the local store.
func (l *Local) setCreator(creator *Creator) error {
	l.mutex.Lock()
	l.creators[creator.domain] = creator
	l.mutex.Unlock()

	data, err := json.MarshalIndent(&l.creators, "", "\t")
	if err != nil {
		return err
	}

	err = writeLocalStore(l.file, data)
	if err != nil {
		return err
	}

	return nil
}

// GetCreator gets creator for domain from internal map, updating the internal
// map if the creator is not in the map.
func (l *Local) GetCreator(domain string) (*Creator, error) {
	c, err := l.common.getCreator(domain)
	if err != nil {
		return nil, err
	}
	if c == nil {
		err = l.refresh()
		if err != nil {
			return nil, err
		}
		c, err = l.common.getCreator(domain)
	}
	return c, err
}

// refresh loads the Creators from the persistent JSON storage into the local
// storage instance.
func (l *Local) refresh() error {
	// Fetch the creators
	cs, err := l.fetchCreators()
	if err != nil {
		return err
	}
	// In a single atomic operation update the reference to the creators.
	l.mutex.Lock()
	l.creators = cs
	l.mutex.Unlock()
	l.timestamp = time.Now()

	return nil
}

// fetch creators reads the Creators from the persistent JSON files and
// converts them from a map of storage items to a map of Creators.
func (l *Local) fetchCreators() (map[string]*Creator, error) {
	cs := make(map[string]*Creator)
	data, err := readLocalStore(l.file)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &cs)
	if err != nil && len(data) > 0 {
		return nil, err
	}

	return cs, nil
}

// readLocalStore reads the contents of a file and returns the binary data.
func readLocalStore(file string) ([]byte, error) {
	err := createLocalStore(file)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// writeLocalStore writes binary data to a file.
func writeLocalStore(file string, data []byte) error {
	err := createLocalStore(file)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// createLocalStore creates the persistent JSON file and any parents specified
// in the path.
func createLocalStore(file string) error {
	if _, err := os.Stat(file); os.IsNotExist(err) {

		if _, err := os.Stat(path.Dir(file)); os.IsNotExist(err) {
			os.MkdirAll(path.Dir(file), 0700)
		}

		_, err = os.Create(file)
		if err != nil {
			return err
		}
	}
	return nil
}
