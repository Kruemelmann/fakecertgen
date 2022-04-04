package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/kruemelmann/fake-certgen/pkg/handlers"
)

func main() {
	r := mux.NewRouter()

	// Register all handlers with the corresponding routes
	r.HandleFunc("/", handlers.HomeHandler)
	r.HandleFunc("/cert", handlers.CertHandler)
	r.HandleFunc("/renew", handlers.RenewHandler)

	// Bind to a port and pass our router in
	log.Fatal(http.ListenAndServe(":9000", r))
}
