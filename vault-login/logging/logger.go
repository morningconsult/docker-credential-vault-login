// Copyright 2018 The Morning Consult, LLC or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//         https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package logging

import (
	log "github.com/cihub/seelog"
	"path/filepath"
)

const DefaultLogFilename string = "vault-login.log"

func SetupLogger(cacheDir string) {
	SetupLoggerWithConfig(getMainLoggerConfig(cacheDir))
}

func SetupTestLogger() {
	SetupLoggerWithConfig(getTestLoggerConfig())
}

func SetupLoggerWithConfig(config string) {
	logger, err := log.LoggerFromConfigAsString(config)
	if err == nil {
		log.ReplaceLogger(logger)
	} else {
		log.Error(err)
	}
}

func getMainLoggerConfig(cacheDir string) string {
	logfile := filepath.Join(cacheDir, "log", DefaultLogFilename)

	return `
<seelog type="asyncloop" minlevel="debug">
	<outputs formatid="main">
		<rollingfile filename="` + logfile + `" type="date"
			datepattern="2006-01-02-15" archivetype="none" maxrolls="2" />
		<filter levels="warn,error,critical">
			<console />
		</filter>
	</outputs>
	<formats>
		<format id="main" format="%UTCDate(2006-01-02T15:04:05Z07:00) [%LEVEL] %Msg%n" />
	</formats>
</seelog>
`
}

func getTestLoggerConfig() string {
	return `
<seelog type="asyncloop">
	<outputs>
		<rollingfile filename="/dev/null" type="date" 
		datepattern="2006-01-02-15" archivetype="none" maxrolls="2" />
	</outputs>
</seelog>
`
}
