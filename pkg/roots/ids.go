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

// Map that stores Certificate Transparency log info associated to their IDs.
var ctLogs map[string]CTLog = make(map[string]CTLog)

// [ctLogs] access lock.
var logMapLock sync.Mutex = sync.Mutex{}

// Get the log client associate to a CT log ID.
func GetLogClient(id string) (*client.LogClient, error) {
	logMapLock.Lock()
	defer logMapLock.Unlock()
	log, ok := ctLogs[id]
	if !ok {
		return nil, ErrUnknownLog
	}

	return client.New(log.Url, http.DefaultClient, jsonclient.Options{PublicKeyDER: log.Key.raw})
}

// Partial JSON scheme of [log_list_google] and [log_list_apple].
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

// Wrapper type for JSON unmarshalling of CT log public keys.
type LogKey struct {
	raw []byte
}

// Decodes a base64-encoded JSON string into a CT log public key.
func (k *LogKey) UnmarshalJSON(bs []byte) (err error) {
	if raw, e := util.B64Dec(bytes.Trim(bs, `"`)); e != nil {
		err = e
	} else {
		k.raw = raw
	}
	return
}

// Load logs from a given log list.
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

// Load logs known to Google.
func FetchGoogleKnownLogs() error {
	return fetchLogs(log_list_google)
}

// Load logs known to Apple.
func FetchAppleKnownLogs() error {
	return fetchLogs(log_list_apple)
}
