// Copyright 2019 The Morning Consult, LLC or its affiliates. All Rights Reserved.
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/mitchellh/go-homedir"
)

const (
	EnvLogDir     = "DCVL_LOG_DIR"
	defaultLogDir = "~/.docker-credential-vault-login"
)

type LoggingOptions struct {
	LogDir string
}

func LogWriter(opts *LoggingOptions) (io.WriteCloser, error) {
	if opts == nil {
		opts = &LoggingOptions{}
	}

	if opts.LogDir == "" {
		opts.LogDir = defaultLogDir
	}

	if v := os.Getenv(EnvLogDir); v != "" {
		opts.LogDir = v
	}

	logDir, err := homedir.Expand(opts.LogDir)
	if err != nil {
		return nil, fmt.Errorf("error expanding logging directory %s: %v", opts.LogDir, err)
	}

	if err = os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("error creating directory %s: %v", logDir, err)
	}

	logfile := filepath.Join(logDir, fmt.Sprintf("vault-login_%s.log", time.Now().Format("2006-01-02")))

	file, err := os.OpenFile(logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("error opening/creating log file %s: %v", logfile, file)
	}

	return file, nil
}
