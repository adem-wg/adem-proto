package roots

import (
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

type CTLog struct {
	KeyDER           []byte
	V1URL            string
	StaticSubmission string
	StaticMonitoring string
}

func (l CTLog) v1URL() string {
	if l.V1URL != "" {
		return l.V1URL
	}
	return l.StaticSubmission
}

func (l CTLog) staticMonitoringURL() string {
	if l.StaticMonitoring != "" {
		return l.StaticMonitoring
	}
	if l.StaticSubmission != "" {
		return l.StaticSubmission
	}
	return l.V1URL
}

var ctLogs map[string]CTLog = make(map[string]CTLog)
var logMapLock sync.Mutex = sync.Mutex{}

func storeLogs(rawJSON []byte) error {
	ll, err := loglist3.NewFromJSON(rawJSON)
	if err != nil {
		return err
	}

	logMapLock.Lock()
	defer logMapLock.Unlock()

	for _, operator := range ll.Operators {
		for _, l := range operator.Logs {
			id := base64.StdEncoding.EncodeToString(l.LogID)
			entry := ctLogs[id]
			entry.KeyDER = append([]byte(nil), l.Key...)
			entry.V1URL = l.URL
			ctLogs[id] = entry
		}

		for _, l := range operator.TiledLogs {
			id := base64.StdEncoding.EncodeToString(l.LogID)
			entry := ctLogs[id]
			entry.KeyDER = append([]byte(nil), l.Key...)
			entry.StaticSubmission = l.SubmissionURL
			entry.StaticMonitoring = l.MonitoringURL
			ctLogs[id] = entry
		}
	}

	return nil
}

func GetLog(id string) (CTLog, error) {
	logMapLock.Lock()
	defer logMapLock.Unlock()

	log, ok := ctLogs[id]
	if !ok {
		return CTLog{}, ErrUnknownLog
	}
	return log, nil
}

func fetchLogs(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return storeLogs(body)
}

func FetchGoogleKnownLogs() error {
	return fetchLogs(loglist3.LogListURL)
}

func FetchAppleKnownLogs() error {
	return fetchLogs("https://valid.apple.com/ct/log_list/current_log_list.json")
}

func ReadKnownLogs(pattern string) error {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}

	for _, path := range matches {
		if bs, err := os.ReadFile(path); err != nil {
			return err
		} else if err := storeLogs(bs); err != nil {
			return err
		}
	}

	return nil
}
