/*
This file implements the checking of root key commitments for the Certificate
Transparency API in v1.
*/
package roots

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/adem-wg/adem-proto/pkg/tokens"
	"github.com/adem-wg/adem-proto/pkg/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var ErrIssNoHostName = errors.New("issuer has no hostname")
var ErrCertNotForIss = errors.New("certificate is not valid for issuer OI")
var ErrCertNotForKey = errors.New("certificate is not valid for key")
var ErrWrongEntryType = errors.New("do not recognize entry type")

// Verify that the rootKey is correctly bound to the issuer OI in the
// certificate's subjects referenced by the CT query.
func VerifyBinding(q CTQueryResult, issuer string, rootKey jwk.Key) error {
	kid, err := tokens.CalcKID(rootKey)
	if err != nil {
		log.Print("could not calculate KID")
		return err
	}
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		log.Print("could not parse issuer")
		return err
	} else if issuerUrl.Hostname() == "" {
		return ErrIssNoHostName
	}

	if !util.Contains(q.subjects, issuerUrl.Hostname()) {
		return ErrCertNotForIss
	} else if !util.Contains(q.subjects, fmt.Sprintf("%s.adem-configuration.%s", kid, issuerUrl.Hostname())) {
		return ErrCertNotForKey
	}
	return nil
}

// Verify that the given certificate hash is included in the log identified by
// the respective client.
func VerifyInclusion(cl *client.LogClient, hash []byte) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Minute))
	defer cancel()

	if sth, err := cl.GetSTH(ctx); err != nil {
		log.Print("could not fetch STH")
		return nil, err
	} else if err := cl.VerifySTHSignature(*sth); err != nil {
		log.Print("STH not valid")
		return nil, err
	} else if respH, err := cl.GetProofByHash(ctx, hash, sth.TreeSize); err != nil {
		log.Print("could not fetch proof by hash")
		return nil, err
	} else if respE, err := cl.GetEntryAndProof(ctx, uint64(respH.LeafIndex), sth.TreeSize); err != nil {
		log.Print("could not fetch entry")
		return nil, err
	} else if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(respH.LeafIndex), sth.TreeSize, hash, respE.AuditPath, sth.SHA256RootHash[:]); err != nil {
		log.Print("could not verify inclusion proof")
		return nil, err
	} else {
		var certT ct.CertificateTimestamp
		if _, err := tls.Unmarshal(respE.LeafInput, &certT); err != nil {
			log.Print("could not parse certificate timestamp")
			return nil, err
		} else {
			var cert *x509.Certificate
			var err error
			if certT.EntryType == ct.PrecertLogEntryType {
				cert, err = x509.ParseTBSCertificate(certT.PrecertEntry.TBSCertificate)
			} else if certT.EntryType == ct.X509LogEntryType {
				cert, err = x509.ParseCertificate(certT.X509Entry.Data)
			} else {
				err = ErrWrongEntryType
			}
			if err != nil {
				log.Print("could not parse certificate")
				return nil, err
			} else {
				return append(cert.DNSNames, cert.Subject.CommonName), nil
			}
		}
	}
}
