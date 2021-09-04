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
	"reflect"
)

// Configuration details from appsettings.json for access to the AWS or Azure
// storage.
type Configuration struct {
	Scheme                string `json:"scheme"` // The scheme to use for requests
	BackgroundColor       string `json:"backgroundColor"`
	MessageColor          string `json:"messageColor"`
	Debug                 bool   `json:"debug"`
	AzureStorageAccount   string `json:"azureStorageAccount"`
	AzureStorageAccessKey string `json:"azureStorageAccessKey"`
	GcpProject            string `json:"gcpProject"`
	OwidFile              string `json:"owidFile"`
	AwsEnabled            string `json:"awsEnabled"`
	OwidStore             string `json:"owidStore"`
}

// NewConfig creates a new instance of configuration from the file provided. If
// the file does not contain a value for some important fields then the
// environment is checked to see if there is corresponding value present there.
func NewConfig(file string) Configuration {
	var c Configuration
	configFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		defer configFile.Close()
		json.NewDecoder(configFile).Decode(&c)
		c.setFromEnvironment("AZURE_STORAGE_ACCOUNT", "AzureStorageAccount")
		c.setFromEnvironment("AZURE_STORAGE_ACCESS_KEY", "AzureStorageAccessKey")
		c.setFromEnvironment("GCP_PROJECT", "GcpProject")
		c.setFromEnvironment("OWID_FILE", "OwidFile")
		c.setFromEnvironment("AWS_ENABLED", "AwsEnabled")
		c.setFromEnvironment("OWID_STORE", "OwidStore")
	}
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

// setFromEnvironment checks if the k field in the configuration has a value.
// If it doesn't then it checks the environment variables to see if they have
// a value for the key e. If so then that value is used in the configuration.
func (c *Configuration) setFromEnvironment(e string, k string) {
	v := reflect.ValueOf(c).Elem()
	if v.FieldByName(k).String() == "" {
		ev := os.Getenv(e)
		if ev != "" {
			v.FieldByName(k).SetString(ev)
		}
	}
}
