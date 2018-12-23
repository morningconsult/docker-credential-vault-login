package logging

import (
	"path/filepath"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mitchellh/go-homedir"
)

const (
	envLogDir = "DOCKER_CREDS_LOG_DIR"
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

	if v := os.Getenv(envLogDir); v != "" {
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