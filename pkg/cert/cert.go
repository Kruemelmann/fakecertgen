package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

var (
	lock     = &sync.Mutex{}
	instance *Certificate
)

type Certificate struct {
	cert       *x509.Certificate
	PrivKey    *rsa.PrivateKey
	PrivKeyPEM *bytes.Buffer
	PEM        *bytes.Buffer
}

func GetCertificate() *Certificate {
	lock.Lock()
	defer lock.Unlock()
	if instance == nil {
		newcrt, err := initCertificate()
		if err != nil {
			log.Fatal(err)
		}
		instance = newcrt
	}
	return instance
}

func RenewCertificate() {
	lock.Lock()
	defer lock.Unlock()
	instance = nil
	newcrt, err := initCertificate()
	if err != nil {
		log.Fatal(err)
	}
	instance = newcrt
}

func initCertificate() (*Certificate, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"dummy, INC."},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{"noobland"},
			StreetAddress: []string{"beginner street"},
			PostalCode:    []string{"123456"},
		},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	//get the ca
	ca := *GetCA()

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, &certPrivKey.PublicKey, ca.PrivKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	newcert := &Certificate{
		cert:       cert,
		PEM:        certPEM,
		PrivKeyPEM: certPrivKeyPEM,
	}
	return newcert, nil
}
