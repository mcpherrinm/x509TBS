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
	KeyUsage:              x509TBS.KeyUsageCertSign | x509TBS.KeyUsageCRLSign,
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

	der := must(x509TBS.SignTBS(rand.Reader, tbs, x509TBS.ECDSAWithSHA256, ecdsaWithSHA256, priv))
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

// TestCreateRevocationList asserts that the end-to-end CreateRevocationList
// path is unchanged after the TBS extraction.
func TestCreateRevocationList(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	issuerDER := must(x509TBS.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv))
	issuer := must(x509TBS.ParseCertificate(issuerDER))

	crlTemplate := &x509TBS.RevocationList{
		Number:     big.NewInt(7),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509TBS.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(99),
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}

	der := must(x509TBS.CreateRevocationList(rand.Reader, crlTemplate, issuer, priv))
	rl := must(x509TBS.ParseRevocationList(der))

	if err := rl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
	if rl.Number.Cmp(crlTemplate.Number) != 0 {
		t.Fatalf("Parsed CRL Number mismatch: %v != %v", rl.Number, crlTemplate.Number)
	}
	if len(rl.RevokedCertificateEntries) != 1 || rl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(99)) != 0 {
		t.Fatalf("unexpected revoked entries: %+v", rl.RevokedCertificateEntries)
	}
}

// TestCreateCertificateRequest asserts that the end-to-end
// CreateCertificateRequest path is unchanged after the TBS extraction.
func TestCreateCertificateRequest(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	csrTemplate := &x509TBS.CertificateRequest{
		Subject:  pkix.Name{CommonName: "create-csr-test"},
		DNSNames: []string{"create.example.com"},
	}

	der := must(x509TBS.CreateCertificateRequest(rand.Reader, csrTemplate, priv))
	csr := must(x509TBS.ParseCertificateRequest(der))

	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	if csr.Subject.CommonName != csrTemplate.Subject.CommonName {
		t.Fatalf("Parsed CSR does not match expected subject, %s != %s", csr.Subject.CommonName, csrTemplate.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "create.example.com" {
		t.Fatalf("Parsed CSR DNSNames mismatch: %v", csr.DNSNames)
	}
}

func TestTBSRevocationList(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	ecdsaWithSHA256 := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
	}

	// Need a parsed issuer cert so SubjectKeyId is populated.
	issuerDER := must(x509TBS.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv))
	issuer := must(x509TBS.ParseCertificate(issuerDER))

	crlTemplate := &x509TBS.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509TBS.RevocationListEntry{
			{
				SerialNumber:   big.NewInt(42),
				RevocationTime: time.Now().Add(-time.Minute),
			},
		},
	}

	tbs := must(x509TBS.CreateTBSRevocationList(crlTemplate, issuer, ecdsaWithSHA256))

	// Lint the TBS, log it, etc

	parsedTBS := must(x509TBS.ParseTBSRevocationList(tbs))
	if parsedTBS.Number.Cmp(crlTemplate.Number) != 0 {
		t.Fatalf("Parsed TBS CRL Number mismatch: %v != %v", parsedTBS.Number, crlTemplate.Number)
	}
	if len(parsedTBS.RevokedCertificateEntries) != 1 || parsedTBS.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("Parsed TBS CRL entries mismatch: %+v", parsedTBS.RevokedCertificateEntries)
	}

	der := must(x509TBS.SignTBS(rand.Reader, tbs, x509TBS.ECDSAWithSHA256, ecdsaWithSHA256, priv))
	rl := must(x509TBS.ParseRevocationList(der))

	if err := rl.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}

	if len(rl.RevokedCertificateEntries) != 1 || rl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("unexpected revoked entries: %+v", rl.RevokedCertificateEntries)
	}
}

func TestTBSCertificateRequest(t *testing.T) {
	priv := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	ecdsaWithSHA256 := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
	}

	csrTemplate := &x509TBS.CertificateRequest{
		Subject:  pkix.Name{CommonName: "csr-test"},
		DNSNames: []string{"example.com"},
	}

	tbs := must(x509TBS.CreateTBSCertificateRequest(csrTemplate, &priv.PublicKey))

	// Lint the TBS, log it, etc

	parsedTBS := must(x509TBS.ParseTBSCertificateRequest(tbs))
	if parsedTBS.Subject.CommonName != csrTemplate.Subject.CommonName {
		t.Fatalf("Parsed TBS CSR does not match expected subject, %s != %s", parsedTBS.Subject.CommonName, csrTemplate.Subject.CommonName)
	}
	if len(parsedTBS.DNSNames) != 1 || parsedTBS.DNSNames[0] != "example.com" {
		t.Fatalf("Parsed TBS CSR DNSNames mismatch: %v", parsedTBS.DNSNames)
	}

	der := must(x509TBS.SignTBS(rand.Reader, tbs, x509TBS.ECDSAWithSHA256, ecdsaWithSHA256, priv))
	csr := must(x509TBS.ParseCertificateRequest(der))

	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}

	if csr.Subject.CommonName != csrTemplate.Subject.CommonName {
		t.Fatalf("Parsed CSR does not match expected subject, %s != %s", csr.Subject.CommonName, csrTemplate.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "example.com" {
		t.Fatalf("Parsed CSR DNSNames mismatch: %v", csr.DNSNames)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
