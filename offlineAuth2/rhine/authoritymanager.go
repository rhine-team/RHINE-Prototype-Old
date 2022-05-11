package rhine

import (
	"crypto/rand"
	"encoding/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"math/big"
	"time"
)

type AuthorityManager struct {
	ca      Authority
	privkey any
	cacert  *x509.Certificate
}

func (am AuthorityManager) CreatePoisonedCert(psr *Psr) *x509.Certificate {

	certTemplate := x509.Certificate{
		SerialNumber: big.NewInt(123),
		Issuer:       am.cacert.Issuer,
		Subject:      psr.csr.csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     psr.csr.exp,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{psr.csr.csr.DNSNames[0]},
	}
	rhinext, _ := psr.csr.CreateCSRExtension()

	certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, rhinext)

	certTemplate.Extensions = append(certTemplate.Extensions, pkix.Extension{
		Id:       x509.OIDExtensionCTPoison,
		Critical: true,
		Value:    asn1.NullBytes,
	})

	certbytes, _ := x509.CreateCertificate(rand.Reader, &certTemplate, am.cacert, psr.csr.csr.PublicKey, am.privkey)

	cert, _ := x509.ParseCertificate(certbytes)

	return cert

}