package logging

import (
        "fmt"
        "path/filepath"
        "os"

        log "github.com/cihub/seelog"
        homedir "github.com/mitchellh/go-homedir"
)

const (
        EnvCacheDir string = "DOCKER_CREDS_CACHE_DIR"
        DefaultCacheDir string = "~/.docker-credential-vault-login"
        DefaultLogFilename string = "vault-login.log"
        BackupLogFilename string = "/tmp/.docker-credential-vault-login/log/vault-login.log"
)


func SetupLogger() {
        var cacheDir = DefaultCacheDir
        if v := os.Getenv(EnvCacheDir); v != "" {
                cacheDir = DefaultCacheDir
        }
        
        reducedFilename := filepath.Join(cacheDir, "log", DefaultLogFilename)
        logfile, err := homedir.Expand(reducedFilename)
        if err != nil {
                fmt.Printf("Failed to create log file at %q.\nCreating log file at %q instead.\n",
                        reducedFilename, BackupLogFilename)
                logfile = BackupLogFilename
        }

        logfile = filepath.Clean(logfile)

        config := `
        <seelog type="asyncloop" minlevel="debug">
                <outputs formatid="main">
                        <rollingfile filename="` + logfile + `" type="date" datepattern="2006-01-02" 
                        archivetype="none" maxrolls="3" />
                        <filter levels="warn,error,critical">
				<console />
			</filter>
                </outputs>
                <formats>
                        <format id="main" format="%UTCDate(2006-01-02T15:04:05Z07:00) [%Level] %Msg%n" />
                </formats>
        </seelog>
        `
        
        logger, err := log.LoggerFromConfigAsString(config)
	if err == nil {
		log.ReplaceLogger(logger)
	} else {
		log.Error(err)
	}
}
