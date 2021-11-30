package main

import (
	"flag"
	"log"
	"net/http"
)

type jwtData struct {
	ISS string `json:"iss"`
	SHA256 string `json:"sha256"`
}

func main () {
	var (
		secret *string = flag.String("secret", "-default-secret--default-secret-", "JWT Secret")
		issuer *string = flag.String("iss", "chromatic", "Issuer expected in JWT")
		address *string = flag.String("address", ":4321", "Address to listen on")
	)
	flag.Parse()

	http.Handle("/", withWebhookSignature(*secret, *issuer, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte{'O','K'})
	}))

	log.Printf("Starting server on %s", *address)
  log.Fatal(http.ListenAndServe(*address, nil))
}