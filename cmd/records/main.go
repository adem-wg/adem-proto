/*
This tool converts CBOR arrays of ADEM tokens and COSE keys to the hexadecimal
presentation used by the DNS tooling. Tokens and keys are detected from their
CBOR structure rather than from file extensions.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var quoted bool

func init() {
	flag.BoolVar(&quoted, "quoted", false, "quote each output line as DNS TXT record contents")
}

func printLn(format string, values ...any) {
	line := fmt.Sprintf(format, values...)
	if quoted {
		line = strconv.Quote(line)
	}
	fmt.Println(line)
}

func itemKind(raw []byte) (string, error) {
	if len(raw) > 0 && raw[0]>>5 == 5 {
		if _, err := tokens.ParseKey(raw); err != nil {
			return "", fmt.Errorf("invalid COSE_Key: %w", err)
		}
		return "key", nil
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(raw); err == nil {
		return "token", nil
	}
	return "", fmt.Errorf("CBOR item is neither a COSE_Key nor COSE_Sign1 token")
}

func printFile(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("cannot read %s: %s", path, err)
		return
	}

	var items []cbor.RawMessage
	err = cbor.Unmarshal(raw, &items)
	if err != nil {
		log.Printf("cannot decode %s as a CBOR array: %s", path, err)
		return
	}
	for _, item := range items {
		kind, err := itemKind(item)
		if err != nil {
			log.Printf("cannot use item from %s: %s", path, err)
			continue
		}
		printLn("adem-%s=%s", kind, hex.EncodeToString(item))
	}
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.PrintDefaults()
		log.Fatal("no input")
	}
	for _, path := range flag.Args() {
		printFile(path)
	}
}
