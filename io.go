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
	"bytes"
	"fmt"

	"github.com/SWAN-community/common-go"
)

func readSignature(b *bytes.Buffer) ([]byte, error) {
	return common.ReadByteArrayNoLength(b, signatureLength)
}

func writeSignature(b *bytes.Buffer, v []byte) error {
	if len(v) != signatureLength {
		return fmt.Errorf(
			"provided signature length '%d' not compaitable with '%d' "+
				"OWID signature length",
			len(v),
			signatureLength)
	}
	return common.WriteByteArrayNoLength(b, v)
}
