package roots

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/certificate-transparency-go/loglist3"
)

var ErrUnknownLog = errors.New("unknown log")

type V1Log struct {
	KeyDER []byte
	URL    string
}

type StaticLog struct {
	KeyDER        []byte
	MonitoringURL string
}

var v1Logs map[string]V1Log = make(map[string]V1Log)
var staticLogs map[string]StaticLog = make(map[string]StaticLog)
var logMapLock sync.Mutex = sync.Mutex{}

func storeLogs(rawJSON []byte) error {
	if ll, err := loglist3.NewFromJSON(rawJSON); err != nil {
		return err
	} else {
		logMapLock.Lock()
		defer logMapLock.Unlock()

		for _, operator := range ll.Operators {
			for _, l := range operator.Logs {
				id := LogIDToString(l.LogID)
				v1Logs[id] = V1Log{
					KeyDER: bytes.Clone(l.Key),
					URL:    l.URL,
				}
			}

			for _, l := range operator.TiledLogs {
				id := LogIDToString(l.LogID)
				staticLogs[id] = StaticLog{
					KeyDER:        bytes.Clone(l.Key),
					MonitoringURL: l.MonitoringURL,
				}
			}
		}

		return nil
	}
}

func LogIDToString(id []byte) string {
	return base64.StdEncoding.EncodeToString(id)
}

func GetV1Log(id []byte) (V1Log, error) {
	logMapLock.Lock()
	defer logMapLock.Unlock()

	if log, ok := v1Logs[LogIDToString(id)]; !ok {
		return V1Log{}, ErrUnknownLog
	} else {
		return log, nil
	}
}

func GetStaticLog(id []byte) (StaticLog, error) {
	logMapLock.Lock()
	defer logMapLock.Unlock()

	if log, ok := staticLogs[LogIDToString(id)]; !ok {
		return StaticLog{}, ErrUnknownLog
	} else {
		return log, nil
	}
}

func fetchLogs(url string) error {
	if resp, err := http.Get(url); err != nil {
		return err
	} else {
		defer resp.Body.Close()

		if body, err := io.ReadAll(resp.Body); err != nil {
			return err
		} else {
			return storeLogs(body)
		}
	}
}

func FetchGoogleKnownLogs() error {
	return fetchLogs(loglist3.LogListURL)
}

func FetchAppleKnownLogs() error {
	return fetchLogs("https://valid.apple.com/ct/log_list/current_log_list.json")
}

func ReadKnownLogs(pattern string) error {
	if matches, err := filepath.Glob(pattern); err != nil {
		return err
	} else {
		for _, path := range matches {
			if bs, err := os.ReadFile(path); err != nil {
				return err
			} else if err := storeLogs(bs); err != nil {
				return err
			}
		}

		return nil
	}
}
