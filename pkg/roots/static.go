package roots

import (
	"context"
	"crypto/x509"
	"time"

	"filippo.io/sunlight"
)

func verifyStaticInclusion(cl *sunlight.Client, index uint64) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Minute))
	defer cancel()

	checkpoint, _, err := cl.Checkpoint(ctx)
	if err != nil {
		return nil, err
	}

	entry, _, err := cl.Entry(ctx, checkpoint.Tree, int64(index))
	if err != nil {
		return nil, err
	}

	rawCert := entry.Certificate
	if entry.IsPrecert {
		rawCert = entry.PreCertificate
	}

	cert, err := x509.ParseCertificate(rawCert)
	if err != nil {
		return nil, err
	}
	return append(cert.DNSNames, cert.Subject.CommonName), nil
}
