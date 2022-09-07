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
	"fmt"
	"log"

	"github.com/SWAN-community/config-go"
)

// Configuration details from appsettings.json for access to the AWS, Azure, or
// GCP storage.
type Configuration struct {
	config.Base `mapstructure:",squash"`
	OwidFile    string `mapstructure:"owidFile"`
	OwidStore   string `mapstructure:"owidStore"`
}

// NewConfig creates a new instance of configuration from the file provided. If
// the file does not contain a value for some important fields then the
// environment is checked to see if there is corresponding value present there.
func NewConfig(file string) Configuration {
	var c Configuration
	err := config.LoadConfig([]string{"."}, file, &c)
	if err != nil {
		fmt.Println(err.Error())
	}
	return c
}

// Log prints non sensitive configuration fields to the logger.
func (c *Configuration) Log() {
	log.Printf("OWID:Debug Mode: %t\n", c.Debug)
	log.Printf("OWID:File : %s\n", c.OwidFile)
}
