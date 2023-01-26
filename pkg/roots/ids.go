package roots

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var ErrUnknownLog = errors.New("unknown log")

const log_list_google = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
const log_list_apple = "https://valid.apple.com/ct/log_list/current_log_list.json"

var ctLogs map[string]CTLog = make(map[string]CTLog)
var logMapLock sync.Mutex = sync.Mutex{}

func GetLogClient(id string) (*client.LogClient, error) {
	logMapLock.Lock()
	defer logMapLock.Unlock()
	log, ok := ctLogs[id]
	if !ok {
		return nil, ErrUnknownLog
	}

	return client.New(log.Url, http.DefaultClient, jsonclient.Options{PublicKeyDER: log.Key.raw})
}

type KnownLogs struct {
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Logs []CTLog `json:"logs"`
}

type CTLog struct {
	Key LogKey `json:"key"`
	Id  string `json:"log_id"`
	Url string `json:"url"`
}

type LogKey struct {
	raw []byte
}

func (k *LogKey) UnmarshalJSON(bs []byte) (err error) {
	if raw, e := util.B64Dec(bytes.Trim(bs, `"`)); e != nil {
		err = e
	} else {
		k.raw = raw
	}
	return
}

func fetchLogs(url string) error {
	logMapLock.Lock()
	defer logMapLock.Unlock()

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	logs := KnownLogs{}
	err = json.Unmarshal(body, &logs)
	if err != nil {
		return err
	}

	for _, operator := range logs.Operators {
		for _, l := range operator.Logs {
			ctLogs[l.Id] = l
		}
	}

	return nil
}

func FetchGoogleKnownLogs() error {
	return fetchLogs(log_list_google)
}

func FetchAppleKnownLogs() error {
	return fetchLogs(log_list_apple)
}
