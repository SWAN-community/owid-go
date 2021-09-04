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
	"testing"
)

func TestLocalConfigurationSettings(t *testing.T) {
	c := NewConfig("appsettings.test.local.json")
	if c.OwidFile == "" {
		t.Error("OWID file not set")
		return
	}
}

func TestLocalConfigurationEnvironment(t *testing.T) {
	e := "TEST ENV OWID FILE"
	t.Setenv("OWID_FILE", e)
	c := NewConfig("appsettings.test.none.json")
	if c.OwidFile != e {
		t.Error("OWID file not expected value")
		return
	}
}

func TestAwsConfigurationSettings(t *testing.T) {
	c := NewConfig("appsettings.test.aws.json")
	if c.AwsEnabled == "" {
		t.Error("AWS Enabled not set")
		return
	}
}

func TestAwsConfigurationEnvironment(t *testing.T) {
	e := "true"
	t.Setenv("AWS_ENABLED", e)
	c := NewConfig("appsettings.test.none.json")
	if c.AwsEnabled != e {
		t.Error("AWS Enabled not expected value")
		return
	}
}

func TestGcpConfigurationSettings(t *testing.T) {
	c := NewConfig("appsettings.test.gcp.json")
	if c.GcpProject == "" {
		t.Error("GCP Project not set")
		return
	}
}

func TestGcpConfigurationEnvironment(t *testing.T) {
	e := "PROJECT NAME"
	t.Setenv("GCP_PROJECT", e)
	c := NewConfig("appsettings.test.none.json")
	if c.GcpProject != e {
		t.Error("GCP Project not expected value")
		return
	}
}

func TestAzureConfigurationSettings(t *testing.T) {
	c := NewConfig("appsettings.test.azure.json")
	if c.AzureStorageAccount == "" || c.AzureStorageAccessKey == "" {
		t.Error("Azure not set")
		return
	}
}

func TestAzureConfigurationEnvironment(t *testing.T) {
	ea := "ACCOUNT"
	ek := "KEY"
	t.Setenv("AZURE_STORAGE_ACCOUNT", ea)
	t.Setenv("AZURE_STORAGE_ACCESS_KEY", ek)
	c := NewConfig("appsettings.test.none.json")
	if c.AzureStorageAccount != ea || c.AzureStorageAccessKey != ek {
		t.Error("Azure not expected value")
		return
	}
}
