package handlers

import "net/http"

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("fake-cert:\n  /cert -> get the current certificate\n  /renew -> generate a new certificate"))
}
