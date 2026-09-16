/*
This tool probes for ADEM tokens and untrusted verification keys. DNS TXT
payloads use hexadecimal CBOR. Stdout is a CBOR array of COSE_Sign1 tokens;
the optional -keys-out file is a CBOR array of the discovered COSE keys.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

func init() {
	args.AddProbeArgs()
	flag.StringVar(&keysOutPath, "keys-out", "", "write discovered COSE keys as a CBOR array to this file")
}

var keysOutPath string
var recordPattern = regexp.MustCompile(`^adem-(token|key)(?:-.+)?=([[:xdigit:]]+)$`)

func probeDNS(name string) ([]*cose.Sign1Message, []*cose.Key, error) {
	records, err := net.LookupTXT(name)
	if err != nil {
		return nil, nil, err
	}

	messages := make([]*cose.Sign1Message, 0)
	keys := make([]*cose.Key, 0)
	for _, record := range records {
		match := recordPattern.FindStringSubmatch(record)
		if match == nil {
			continue
		}
		item, err := hex.DecodeString(match[2])
		if err != nil {
			return nil, nil, fmt.Errorf("decode %s record: %w", match[1], err)
		}
		if match[1] == "key" {
			key, err := tokens.ParseKey(item)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid COSE_Key record: %w", err)
			}
			keys = append(keys, key)
		} else {
			message := cose.NewSign1Message()
			if err := message.UnmarshalCBOR(item); err != nil {
				return nil, nil, fmt.Errorf("invalid COSE_Sign1 record: %w", err)
			}
			messages = append(messages, message)
		}
	}

	log.Printf("probed %d token(s) and %d key(s) via DNS", len(messages), len(keys))
	return messages, keys, nil
}

func writeResults(messages []*cose.Sign1Message, keys []*cose.Key) error {
	encodedMessages, err := cbor.Marshal(messages)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(encodedMessages); err != nil {
		return err
	}
	if keysOutPath == "" {
		if len(keys) > 0 {
			log.Printf("discarding %d key(s); use -keys-out to store them", len(keys))
		}
		return nil
	}
	encodedKeys, err := cbor.Marshal(keys)
	if err != nil {
		return err
	}
	return os.WriteFile(keysOutPath, encodedKeys, 0o600)
}

func main() {
	flag.Parse()
	if !args.ProbeDNS() {
		log.Fatal("no probe mechanisms enabled")
	}
	messages, keys, err := probeDNS(args.LoadProbeTarget())
	if err != nil {
		log.Fatalf("could not probe DNS: %s", err)
	}
	if err := writeResults(messages, keys); err != nil {
		log.Fatalf("could not write probe results: %s", err)
	}
}
