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
	"os"
	"path/filepath"
	"io/ioutil"
	"strings"
	"testing"
	log "github.com/cihub/seelog"
)

func TestMainLogger(t *testing.T) {
	abspath, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}

	cleanup(t, abspath)
	defer cleanup(t, abspath)

	SetupLogger(abspath)
	errmsg := "i am a unique error message for testing purposes"
	log.Debug(errmsg)
	log.Flush()

	data, err := ioutil.ReadFile(filepath.Join(abspath, "log", DefaultLogFilename))
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "[DEBUG] "+errmsg) {
		t.Fatalf("log file did not contain error message")
	}
}

func TestTestLogger(t *testing.T) {
	abspath, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}

	cleanup(t, abspath)
	defer cleanup(t, abspath)

	SetupTestLogger()
	log.Debug("i am an error message")
	log.Flush()

	// Check that no files were written to the log directory
	_, err = os.Open(filepath.Join(abspath, "log", DefaultLogFilename))
	if !os.IsNotExist(err) {
		t.Fatalf("expected an os.ErrIsNotExist error, but received the following error instead: %v", err)
	}
}

func TestSetupLoggerError(t *testing.T) {
	SetupLoggerWithConfig("asdfasdf") // should do nothing
}

func cleanup(t *testing.T, logDir string) {
	logFiles, err := filepath.Glob(filepath.Join(logDir, "log", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, logFile := range logFiles {
		os.Remove(logFile)
	}
}