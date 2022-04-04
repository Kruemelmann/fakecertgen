package handlers

import (
	"net/http"

	"github.com/kruemelmann/fake-certgen/pkg/cert"
)

func RenewHandler(w http.ResponseWriter, r *http.Request) {
	cert.RenewCertificate()
	w.Write([]byte("done\n"))
}
