package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func init() {
	args.AddPublicKeyAlgArgs()
	flag.BoolVar(&quoted, "quoted", false, "quote each output line as DNS TXT record contents")
}

var quoted bool

func printLn(format string, ins ...any) {
	s := fmt.Sprintf(format, ins...)
	if quoted {
		s = strconv.Quote(s)
	}
	fmt.Println(s)
}

func printTokens(path string) {
	fp, err := os.Open(path)
	if err != nil {
		log.Fatalf("could not read file: %s", err)
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		token := scanner.Text()
		if token != "" {
			printLn("adem-token=%s", token)
		}
	}
}

func printKeys(keys jwk.Set, alg jwa.SignatureAlgorithm, setAlg bool) {
	if keys == nil {
		log.Fatal("key set is nil")
	}

	for i := range keys.Len() {
		if k, ok := keys.Key(i); !ok {
			log.Printf("cannot access key at %d", i)
		} else if pk, err := k.PublicKey(); err != nil {
			log.Printf("cannot get key: %s", err)
		} else {
			if setAlg {
				if err := pk.Set("alg", alg); err != nil {
					log.Printf("could not set alg: %s", err)
					continue
				}
			}

			if bJwk, err := json.Marshal(pk); err != nil {
				log.Printf("could not encode key: %s", err)
				continue
			} else {
				printLn("adem-key=%s", bJwk)
			}
		}
	}
}

func main() {
	flag.Parse()
	files := flag.Args()
	if len(files) == 0 {
		flag.PrintDefaults()
		log.Fatalf("no input")
	}

	alg, algOk := args.LoadPKAlgOpt()

	for _, file := range files {
		switch filepath.Ext(file) {
		case ".jws":
			printTokens(file)
		case ".pem":
			if keys, err := args.LoadKeys(file, false); err != nil {
				log.Printf("cannot load keys: %s", err)
			} else {
				printKeys(keys, alg, algOk)
			}
		case ".jwk":
			if keys, err := args.LoadKeys(file, true); err != nil {
				log.Printf("cannot load keys: %s", err)
			} else {
				printKeys(keys, alg, algOk)
			}
		default:
			log.Printf("unsupported file format: %s", file)
		}
	}
}
