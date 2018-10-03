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
