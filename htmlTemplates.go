/* ****************************************************************************
 * Copyright 2020 51 Degrees Mobile Experts Limited
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
	"html/template"
	"strings"
)

var registerTemplate = newHTMLTemplate("register", `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Shared Web State - Register Node</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="data:;base64,=">
</head>
<body style="margin: 0;
    padding: 0;
    font-family: nunito, sans-serif;
    font-size: 16px;
    font-weight: 600;
    background-color: {{ .Services.Config.BackgroundColor }};
    color: {{ .Services.Config.MessageColor }};
    height: 100vh;         
    display: flex;
    justify-content: center;
    align-items: center;">
    <form action="register" method="GET">
    <table style="text-align: left;">
        <tr>
            <td colspan="3">
                {{ if not .ReadOnly }}
                <p>Register creator '{{ .Domain }}' to a organisation.</p>
                {{ else }}
                <p>Success. Creator '{{ .Domain }}' registered to organisation name '{{ .Name }}'.</p>
                {{ end }}
            </td>
        </tr>
        <tr>
            <td>
                <p><label for="name">Organisation Name</label></p>
            </td>
            <td>
                <p><input type="text" maxlength="20" id="name" name="name" value="{{ .Name }}" {{ if .ReadOnly }}disabled{{ end }}></p>
            </td>
            <td>
                {{ if .DisplayErrors }}
                <p>{{ .NameError }}</p>
                {{ end }}
            </td>
        </tr>
        <tr>
            <td colspan="3">
                {{ if .DisplayErrors }}
                <p>{{ .Error }}</p>
                {{ end }}
            </td>
        </tr>        
        <tr>
            {{ if not .ReadOnly }}
            <td colspan="3" style="text-align: center;">
                <input type="submit">
            </td>
            {{ end }}
        </tr>        
    </table>
    </form>
</body>
</html>`)

func newHTMLTemplate(n string, h string) *template.Template {
	c := removeHTMLWhiteSpace(h)
	return template.Must(template.New(n).Parse(c))
}

// Removes white space from the HTML string provided whilst retaining valid
// HTML.
func removeHTMLWhiteSpace(h string) string {
	var sb strings.Builder
	for i, r := range h {

		// Only write out runes that are not control characters.
		if r != '\r' && r != '\n' && r != '\t' {

			// Only write this rune if the rune is not a space, or if it is a
			// space the preceding rune is not a space.
			if i == 0 || r != ' ' || h[i-1] != ' ' {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}
