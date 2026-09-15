package tokens

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/adem-wg/adem-proto/pkg/util"
	"github.com/fxamacker/cbor/v2"
)

// Validate requires exactly one lookup method. The trusted log directory must
// additionally agree with that method before any CT request is made.
func (cfg *LogConfig) Validate() error {
	if cfg == nil {
		return errors.New("nil log entry")
	}
	if id, err := util.B64Dec([]byte(cfg.Id)); err != nil || len(id) != 32 {
		return errors.New("log id must be 32 bytes")
	}
	if (cfg.Hash == nil) == (cfg.Index == nil) {
		return errors.New("log entry requires exactly one of hash and index")
	}
	if cfg.Hash != nil && len(cfg.Hash.Raw) != 32 {
		return errors.New("leaf hash must be 32 bytes")
	}
	return nil
}

func encodeLogs(logs Log) ([]any, error) {
	if len(logs) == 0 {
		return nil, errors.New("empty log header")
	}
	entries := make([]any, 0, len(logs))
	for _, cfg := range logs {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		id, _ := util.B64Dec([]byte(cfg.Id))
		entry := map[string]any{"id": id}
		if cfg.Hash != nil {
			entry["hash"] = cfg.Hash.Raw
		} else {
			entry["index"] = *cfg.Index
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func decodeLogs(value any) (Log, error) {
	b, err := CBOR.Marshal(value)
	if err != nil {
		return nil, err
	}
	var entries []map[string]cbor.RawMessage
	if err := strictCBOR.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("empty log header")
	}
	logs := make(Log, 0, len(entries))
	for _, entry := range entries {
		for name := range entry {
			if name != "id" && name != "hash" && name != "index" {
				return nil, fmt.Errorf("unsupported log field %q", name)
			}
		}
		var id []byte
		if err := strictCBOR.Unmarshal(entry["id"], &id); err != nil {
			return nil, err
		}
		cfg := &LogConfig{Id: base64.StdEncoding.EncodeToString(id)}
		if raw, ok := entry["hash"]; ok {
			var hash []byte
			if err := strictCBOR.Unmarshal(raw, &hash); err != nil {
				return nil, err
			}
			cfg.Hash = &LeafHash{Raw: hash, B64: base64.StdEncoding.EncodeToString(hash)}
		}
		if raw, ok := entry["index"]; ok {
			// Unmarshal into uint64 alone would also accept null as zero.
			var index any
			if err := strictCBOR.Unmarshal(raw, &index); err != nil {
				return nil, err
			}
			n, ok := index.(uint64)
			if !ok {
				return nil, errors.New("log index must be a CBOR unsigned integer")
			}
			cfg.Index = &n
		}
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		logs = append(logs, cfg)
	}
	return logs, nil
}
