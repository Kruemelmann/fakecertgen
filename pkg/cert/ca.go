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
	"sync"
	"time"
)

var (
	calock     = &sync.Mutex{}
	cainstance *Certificate
)

func GetCA() *Certificate {
	calock.Lock()
	defer calock.Unlock()
	if instance == nil {
		newca, err := initCA()
		if err != nil {
			log.Fatal(err)
		}
		cainstance = newca
	}
	return cainstance
}

func initCA() (*Certificate, error) {
	cacert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"dummy, INC."},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{"noobland"},
			StreetAddress: []string{"beginner street"},
			PostalCode:    []string{"123456"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	//generate the CA Pricate Key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	//create a cert for the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, cacert, cacert, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	newca := &Certificate{
		cert:       cacert,
		PrivKey:    caPrivKey,
		PEM:        caPEM,
		PrivKeyPEM: caPrivKeyPEM,
	}

	writeToFile("/certs/ca.pem", newca.PEM.Bytes())
	return newca, nil
}
