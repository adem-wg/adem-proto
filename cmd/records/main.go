// records emits one uppercase hexadecimal IHLE RDATA field per line.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/adem-wg/adem-proto/pkg/args"
	"github.com/adem-wg/adem-proto/pkg/tokens"
)

func main() {
	args.AddPublicKeyAlgArgs()
	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Fatal("provide .cwt (hex lines), .cbor (binary CWT or COSE_Key), or .pem key files")
	}
	alg, algOK := args.LoadPKAlgOpt()
	for _, path := range flag.Args() {
		switch filepath.Ext(path) {
		case ".cwt", ".hex":
			f, err := os.Open(path)
			if err != nil {
				log.Fatal(err)
			}
			items, err := tokens.ReadText(f)
			f.Close()
			if err != nil {
				log.Fatal(err)
			}
			for _, raw := range items {
				fmt.Println(tokens.Text(raw))
			}
		case ".cbor":
			raw, err := os.ReadFile(path)
			if err != nil {
				log.Fatal(err)
			}
			if err := tokens.ValidateRecord(raw); err != nil {
				log.Fatal(err)
			}
			fmt.Println(tokens.Text(raw))
		case ".pem":

			ks, err := args.LoadKeys(path)
			if err != nil {
				log.Fatal(err)
			}
			for _, k := range ks {
				if algOK {
					k, err = tokens.WithAlgorithm(k, alg)
					if err != nil {
						log.Fatal(err)
					}
				}

				raw, err := tokens.EncodePublicCOSEKey(k)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(tokens.Text(raw))
			}
		default:
			log.Fatalf("unsupported format %s; regenerate old JWS files as CWTs", path)
		}
	}
}
