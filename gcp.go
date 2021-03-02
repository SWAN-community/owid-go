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
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	"google.golang.org/api/iterator"
)

// Connect to GCP Firebase. Concrete implementation of store.go

// Firebase is a implementation of owid.Store for GCP's Firebase.
type Firebase struct {
	timestamp time.Time         // The last time the maps were refreshed
	client    *firestore.Client // Firebase app
	common
}

// Fireitem is the Firestore table item representation of a Creator
type Fireitem struct {
	Domain     string
	PrivateKey string
	PublicKey  string
	Name       string
}

// NewFirebase creates a new instance of the Firebase structure
func NewFirebase(project string) (*Firebase, error) {
	var f Firebase

	ctx := context.Background()
	conf := &firebase.Config{ProjectID: project}

	app, err := firebase.NewApp(ctx, conf)

	client, err := app.Firestore(ctx)
	if err != nil {
		log.Fatalln(err)
	}

	f.client = client

	f.mutex = &sync.Mutex{}
	err = f.refresh()
	if err != nil {
		return nil, err
	}
	return &f, nil
}

func (f *Firebase) setCreator(creator *Creator) error {
	ctx := context.Background()
	c := Fireitem{
		Domain:     creator.domain,
		PrivateKey: creator.privateKey,
		PublicKey:  creator.publicKey,
		Name:       creator.name,
	}
	a, err := f.client.Collection(creatorsTableName).Doc(creator.domain).Set(ctx, c)
	fmt.Println(a)
	return err
}

// GetCreator gets creator for domain from internal map, updating the internal
// map if the creator is not in the map.
func (f *Firebase) GetCreator(domain string) (*Creator, error) {
	c, err := f.common.getCreator(domain)
	if err != nil {
		return nil, err
	}
	if c == nil {
		err = f.refresh()
		if err != nil {
			return nil, err
		}
		c, err = f.common.getCreator(domain)
	}
	return c, err
}

func (f *Firebase) refresh() error {
	// Fetch the creators
	cs, err := f.fetchCreators()
	if err != nil {
		return err
	}
	// In a single atomic operation update the reference to the creators.
	f.mutex.Lock()
	f.creators = cs
	f.mutex.Unlock()

	return nil
}

func (f *Firebase) fetchCreators() (map[string]*Creator, error) {
	ctx := context.Background()
	cs := make(map[string]*Creator)

	iter := f.client.Collection(creatorsTableName).Documents(ctx)
	for {
		doc, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var item Fireitem
		err = doc.DataTo(&item)
		if err != nil {
			return nil, err
		}
		cs[item.Domain] = newCreator(
			item.Domain,
			item.PrivateKey,
			item.PublicKey,
			item.Name)
	}
	return cs, nil
}
