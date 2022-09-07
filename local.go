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
	"os"
	"path"
	"sync"
	"time"
)

// Local store implementation for OWID - data is stored in maps in memory and
// persisted on disk using JSON files.
type Local struct {
	storeBase
	timestamp time.Time // The last time the maps were refreshed
	file      string    // file path
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

// GetSigner gets signer for domain from internal map, updating the internal
// map if the signer is not in the map.
func (l *Local) GetSigner(domain string) (*Signer, error) {
	c, err := l.getSigner(domain)
	if err != nil {
		return nil, err
	}
	if c == nil {
		err = l.refresh()
		if err != nil {
			return nil, err
		}
		c, err = l.getSigner(domain)
	}
	return c, err
}

// addKeys inserts a new key for the signer.
func (l *Local) addKeys(d string, key *Keys) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.signers[d].Keys = append(l.signers[d].Keys, key)
	return l.save()
}

// addSigner adds a new Signer to the local store.
func (l *Local) addSigner(signer *Signer) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.signers[signer.Domain] = signer
	return l.save()
}

func (l *Local) save() error {
	data, err := json.MarshalIndent(&l.signers, "", "\t")
	if err != nil {
		return err
	}
	err = writeLocalStore(l.file, data)
	if err != nil {
		return err
	}
	return nil
}

// refresh loads the signers from the persistent JSON storage into the local
// storage instance.
func (l *Local) refresh() error {
	// Fetch the signers
	s, err := l.fetchSigners()
	if err != nil {
		return err
	}
	// Sort the keys in the signers.
	for _, i := range s {
		i.SortKeys()
	}
	// In a single atomic operation update the reference to the signers.
	l.mutex.Lock()
	l.signers = s
	l.mutex.Unlock()
	l.timestamp = time.Now()
	return nil
}

// fetchSigners reads the Signers from the persistent JSON files and converts
// them from a map of storage items to a map of signers keyed on domain.
func (l *Local) fetchSigners() (map[string]*Signer, error) {
	s := make(map[string]*Signer)
	data, err := readLocalStore(l.file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &s)
	if err != nil && len(data) > 0 {
		return nil, err
	}
	return s, nil
}

// readLocalStore reads the contents of a file and returns the binary data.
func readLocalStore(file string) ([]byte, error) {
	err := createLocalStore(file)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
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
	err = os.WriteFile(file, data, 0644)
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
