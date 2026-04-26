package x509TBS_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/mcpherrinm/x509TBS"
)

var template = &x509TBS.Certificate{
	SerialNumber:          big.NewInt(1),
	Subject:               pkix.Name{CommonName: "test"},
	NotBefore:             time.Now().Add(-time.Hour),
	NotAfter:              time.Now().Add(time.Hour),
	BasicConstraintsValid: true,
	IsCA:                  true,
	KeyUsage:              x509TBS.KeyUsageCertSign,
}

func TestTBS(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	ecdsaWithSHA256 := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
	}

	tbs := must(x509TBS.CreateTBSCertificate(rand.Reader, template, template, &priv.PublicKey, ecdsaWithSHA256))

	// Lint the TBS, log it, etc

	parsed := must(x509TBS.ParseTBSCertificate(tbs))
	if parsed.Subject.CommonName != template.Subject.CommonName {
		t.Fatalf("Parsed TBS certificate does not match expected subject, %s != %s", parsed.Subject.CommonName, template.Subject.CommonName)
	}

	der := must(x509TBS.SignTBSCertificate(rand.Reader, tbs, x509TBS.ECDSAWithSHA256, priv))
	cert := must(x509TBS.ParseCertificate(der))

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
}

// TestCreateCert asserts that CreateCert is unchanged
func TestCreateCert(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	der := must(x509TBS.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv))
	cert := must(x509TBS.ParseCertificate(der))

	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
