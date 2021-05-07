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
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

type Local struct {
	timestamp time.Time // The last time the maps were refreshed
	file      string    // file path
	common
}

type item struct {
	Domain     string
	PrivateKey string
	PublicKey  string
	Name       string
}

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

func (l *Local) setCreator(creator *Creator) error {
	l.mutex.Lock()
	l.creators[creator.domain] = creator
	l.mutex.Unlock()

	cs := make(map[string]*item)

	for k, v := range l.creators {
		cs[k] = &item{
			Domain:     v.domain,
			PrivateKey: v.privateKey,
			PublicKey:  v.publicKey,
			Name:       v.name,
		}
	}

	data, err := json.MarshalIndent(&cs, "", "\t")
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

func (l *Local) fetchCreators() (map[string]*Creator, error) {
	cis := make(map[string]*item)
	cs := make(map[string]*Creator)
	data, err := readLocalStore(l.file)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &cis)
	if err != nil && len(data) > 0 {
		return nil, err
	}

	for k, v := range cis {
		cs[k] = newCreator(v.Domain, v.PrivateKey, v.PublicKey, v.Name)
	}

	return cs, nil
}

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
