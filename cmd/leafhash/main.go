/*
This tool converts a certificate's embedded SCTs into log configs for the
"log" claim of endorsements. For RFC 6962 SCTs it outputs leaf hashes that can
be used in /ct/v1/get-proof-by-hash queries; for Static CT SCTs it outputs the
leaf index advertised in the SCT extension.

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

	"filippo.io/sunlight"
	"github.com/adem-wg/adem-proto/pkg/tokens"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

var certPath string
var preCertPath string

func init() {
	// TODO: Unify arguments
	flag.StringVar(&certPath, "cert", "", "path to certificate or certificate chain; log type is detected automatically")
	flag.StringVar(&preCertPath, "precert-fullchain", "", "legacy alias for -cert when passing a certificate chain")
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

type certType int

const (
	certTypeX509 certType = iota
	certTypeEmbeddedSCT
	certTypePrecertificate
)

func detectCertType(certChain []*x509.Certificate) certType {
	switch {
	case certChain[0].IsPrecertificate():
		return certTypePrecertificate
	case len(certChain[0].SCTList.SCTList) > 0:
		return certTypeEmbeddedSCT
	default:
		return certTypeX509
	}
}

func mkV1Cfg(logID []byte, leaf *ct.MerkleTreeLeaf) (*tokens.LogConfig, error) {
	if hash, err := ct.LeafHashForLeaf(leaf); err != nil {
		return nil, err
	} else {
		cfg := tokens.LogConfig{
			Ver: tokens.LogVersionV1,
			Id:  base64.StdEncoding.EncodeToString(logID),
			Hash: &tokens.LeafHash{
				B64: base64.StdEncoding.EncodeToString(hash[:]),
			},
		}
		return &cfg, nil
	}
}

func mkStaticCfg(logID []byte, sct *ct.SignedCertificateTimestamp) (*tokens.LogConfig, error) {
	ext, err := sunlight.ParseExtensions(sct.Extensions)
	if err != nil {
		return nil, err
	}

	index := tokens.LeafIndex{Value: uint64(ext.LeafIndex)}
	return &tokens.LogConfig{
		Ver:   tokens.LogVersionStatic,
		Id:    base64.StdEncoding.EncodeToString(logID),
		Index: &index,
	}, nil
}

func mkV1Leaf(certChain []*x509.Certificate, certType certType, timestamp uint64) (*ct.MerkleTreeLeaf, error) {
	switch certType {
	case certTypeEmbeddedSCT:
		if len(certChain) < 2 {
			return nil, errors.New("certificate with embedded SCTs requires issuer chain for CT v1 leaf hashes")
		}
		return ct.MerkleTreeLeafForEmbeddedSCT(certChain, timestamp)
	case certTypePrecertificate:
		return ct.MerkleTreeLeafFromChain(certChain, ct.PrecertLogEntryType, timestamp)
	default:
		return ct.MerkleTreeLeafFromChain(certChain, ct.X509LogEntryType, timestamp)
	}
}

func mkCfg(certChain []*x509.Certificate, certType certType, sct *ct.SignedCertificateTimestamp) (*tokens.LogConfig, error) {
	if len(sct.Extensions) > 0 {
		return mkStaticCfg(sct.LogID.KeyID[:], sct)
	}

	leaf, err := mkV1Leaf(certChain, certType, sct.Timestamp)
	if err != nil {
		return nil, err
	}
	return mkV1Cfg(sct.LogID.KeyID[:], leaf)
}

func main() {
	flag.Parse()

	loadPreCert := preCertPath != ""
	loadPath := certPath
	if loadPreCert {
		loadPath = preCertPath
	}
	if loadPath == "" {
		log.Fatal("no certificate provided")
	}

	if certChain, err := loadCerts(loadPath); err != nil {
		log.Fatalf("could not load certificates: %s", err)
	} else {
		// TODO: Detect `certType` in `mkV1Leaf` and remove the respective argument
		// from `mkCfg` and `mkV1Leaf`. Also, do not encode the cert type in a
		// const, but branch directly on the checks. Add comments that document this
		// reasoning.
		certType := detectCertType(certChain)
		logs := []*tokens.LogConfig{}
		for _, serializedSct := range certChain[0].SCTList.SCTList {
			var sct ct.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(serializedSct.Val, &sct); err != nil {
				log.Printf("could not deserialize the sct: %s", err)
			} else {
				if cfg, err := mkCfg(certChain, certType, &sct); err != nil {
					log.Printf("could not build log config: %s", err)
				} else {
					logs = append(logs, cfg)
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
