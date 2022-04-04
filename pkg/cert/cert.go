package cert

import (
	"crypto/x509"
	"sync"
)

var (
	lock     = &sync.Mutex{}
	instance *Certificate
)

type Certificate struct {
	Ca x509.Certificate
}

func NewCertificate() *Certificate {
	lock.Lock()
	defer lock.Unlock()
	if instance == nil {
		instance = generateCertificate()
	}
	return instance
}
