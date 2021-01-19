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
	"fmt"
	"log"
	"os"
)

// Configuration details from appsettings.json for access to the AWS or Azure
// storage.
type Configuration struct {
	Scheme          string `json:"scheme"` // The scheme to use for requests
	BackgroundColor string `json:"backgroundColor"`
	MessageColor    string `json:"messageColor"`
	Debug           bool   `json:"debug"`
}

// NewConfig creates a new instance of configuration from the file provided.
func NewConfig(file string) Configuration {
	var c Configuration
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&c)
	return c
}

// Validate confirms that the configuration is usable.
func (c *Configuration) Validate() error {
	var err error
	log.Printf("OWID:Debug Mode: %t\n", c.Debug)
	if err == nil {
		if c.BackgroundColor != "" {
			log.Printf("OWID:BackgroundColor: %s\n", c.BackgroundColor)
		} else {
			err = fmt.Errorf("OWID BackgroundColor missing in config")
		}
	}
	if err == nil {
		if c.MessageColor != "" {
			log.Printf("OWID:MessageColor: %s\n", c.MessageColor)
		} else {
			err = fmt.Errorf("OWID MessageColor missing in config")
		}
	}
	return err
}
