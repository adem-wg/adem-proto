package roots

import (
	"context"
	"crypto/x509"
	"time"

	"filippo.io/sunlight"
)

func verifyStaticInclusion(cl *sunlight.Client, index int64) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Minute))
	defer cancel()

	if checkpoint, _, err := cl.Checkpoint(ctx); err != nil {
		return nil, err
	} else if entry, _, err := cl.Entry(ctx, checkpoint.Tree, index); err != nil {
		return nil, err
	} else {
		rawCert := entry.Certificate
		if entry.IsPrecert {
			rawCert = entry.PreCertificate
		}

		if cert, err := x509.ParseCertificate(rawCert); err != nil {
			return nil, err
		} else {
			return append(cert.DNSNames, cert.Subject.CommonName), nil
		}
	}
}
