package handlers

import (
	"net/http"

	"github.com/kruemelmann/fake-certgen/pkg/cert"
)

func CertHandler(w http.ResponseWriter, r *http.Request) {
	crt := cert.GetCertificate()
	w.Write(crt.PEM.Bytes())
}
