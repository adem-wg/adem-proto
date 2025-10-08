/*
This tool calculates a certificate's embedded SCTs leaf hashes such that they
can be used in /ct/v1/get-proof-by-hash queries (see [RFC 6962]). The tool
outputs the leaf hashes in JSON encoding for "log" claim of endorsements.

[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962
*/
package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

var certPath string
var preCertPath string

func init() {
	flag.StringVar(&certPath, "cert", "", "path to certificate (must not be pre-certificate)")
	flag.StringVar(&preCertPath, "precert-fullchain", "", "path to file containing pre-certificate and certificate chain")
}

func loadCerts(path string) ([]*x509.Certificate, error) {
	if toDecode, err := os.ReadFile(path); err != nil {
		return nil, err
	} else {
		certs := make([]*x509.Certificate, 0)
		var block *pem.Block
		var rest []byte
		for rest == nil || len(rest) > 0 {
			if block, rest = pem.Decode(toDecode); block == nil {
				return nil, errors.New("could not decode PEM")
			} else {
				toDecode = rest
				if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
					return nil, err
				} else {
					certs = append(certs, cert)
				}
			}
		}
		return certs, nil
	}
}

func mkCfg(logId []byte, leaf *ct.MerkleTreeLeaf) (*tokens.LogConfig, error) {
	if hash, err := ct.LeafHashForLeaf(leaf); err != nil {
		return nil, err
	} else {
		cfg := tokens.LogConfig{
			Ver: "v1",
			Id:  base64.StdEncoding.EncodeToString(logId),
			Hash: tokens.LeafHash{
				B64: base64.StdEncoding.EncodeToString(hash[:]),
			},
		}
		return &cfg, nil
	}
}

func main() {
	flag.Parse()

	loadPreCert := preCertPath != ""
	loadPath := certPath
	if loadPreCert {
		loadPath = preCertPath
	}

	if certChain, err := loadCerts(loadPath); err != nil {
		log.Fatalf("could not load certificates: %s", err)
	} else if tbs, err := x509.RemoveSCTList(certChain[0].RawTBSCertificate); err != nil {
		log.Fatalf("could not remove SCT list: %s", err)
	} else {
		logs := []*tokens.LogConfig{}
		for _, serializedSct := range certChain[0].SCTList.SCTList {
			var sct ct.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(serializedSct.Val, &sct); err != nil {
				log.Printf("could not deserialize the sct: %s", err)
			} else {
				if loadPreCert {
					leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: tbs}, sct.Timestamp)
					if cfg, err := mkCfg(sct.LogID.KeyID[:], leaf); err != nil {
						log.Printf("could not calculate leaf hash: %s", err)
					} else {
						logs = append(logs, cfg)
					}
				} else {
					if leaf, err := ct.MerkleTreeLeafForEmbeddedSCT(certChain, sct.Timestamp); err != nil {
						log.Printf("could not construct precert merkle tree leaf: %s", err)
					} else if cfg, err := mkCfg(sct.LogID.KeyID[:], leaf); err != nil {
						log.Printf("could not calculate leaf hash: %s", err)
					} else {
						logs = append(logs, cfg)
					}
				}
			}
		}

		if len(logs) == 0 {
			log.Print("no SCTs found")
		}
		if bs, err := json.MarshalIndent(logs, "", "  "); err != nil {
			log.Fatalf("could not marshal JSON: %s", err)
		} else {
			fmt.Printf("%s\n", string(bs))
		}
	}
}
