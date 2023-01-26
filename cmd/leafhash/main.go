package main

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"os"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

var certPath string
var issuerCertPath string

func init() {
	flag.StringVar(&certPath, "cert", "", "path to certificate")
	flag.StringVar(&issuerCertPath, "issuer", "", "path to issuer certificate (only necessary for precertificates)")
}

func loadCert(path string) (*x509.Certificate, error) {
	if bs, err := os.ReadFile(path); err != nil {
		return nil, err
	} else if block, rest := pem.Decode(bs); len(rest) != 0 {
		return nil, errors.New("could not decode PEM")
	} else if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	} else {
		return cert, nil
	}
}

func logHash(logId []byte, leaf *ct.MerkleTreeLeaf) error {
	if hash, err := ct.LeafHashForLeaf(leaf); err != nil {
		return err
	} else {
		logId := base64.StdEncoding.EncodeToString(logId)
		leafHash := base64.StdEncoding.EncodeToString(hash[:])
		log.Printf("log ID: %s", logId)
		log.Printf("|- leaf hash: %s", leafHash)
	}
	return nil
}

func main() {
	flag.Parse()

	var issuerCert *x509.Certificate
	if issuerCertPath != "" {
		var err error
		issuerCert, err = loadCert(issuerCertPath)
		if err != nil {
			log.Fatalf("could not load issuer cert: %s", err)
		}
	}

	if cert, err := loadCert(certPath); err != nil {
		log.Fatalf("could not load cert: %s", err)
	} else if tbs, err := x509.RemoveSCTList(cert.RawTBSCertificate); err != nil {
		log.Fatalf("could not remove SCT list: %s", err)
	} else {
		for _, serializedSct := range cert.SCTList.SCTList {
			var sct ct.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(serializedSct.Val, &sct); err != nil {
				log.Printf("could not deserialize the sct: %s", err)
			} else {
				if issuerCert == nil {
					leaf := ct.CreateX509MerkleTreeLeaf(ct.ASN1Cert{Data: tbs}, sct.Timestamp)
					if err := logHash(sct.LogID.KeyID[:], leaf); err != nil {
						log.Printf("could not calculate leaf hash: %s", err)
					}
				} else {
					if leaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*x509.Certificate{cert, issuerCert}, sct.Timestamp); err != nil {
						log.Printf("could not construct precert merkle tree leaf: %s", err)
					} else if err := logHash(sct.LogID.KeyID[:], leaf); err != nil {
						log.Printf("could not calculate leaf hash: %s", err)
					}
				}
			}
		}
	}
}
