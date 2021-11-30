package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt"
)

type jwtData struct {
	ISS string `json:"iss"`
	SHA256 string `json:"sha256"`
}

func main () {
	var (
		secret *string = flag.String("secret", "-default-secret--default-secret-", "JWT Secret")
		iss *string = flag.String("iss", "chromatic", "Issuer expected in JWT")
		address *string = flag.String("address", ":4321", "Address to listen on")
	)
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Webhook-Signature")
		if signature == "" {
			log.Println("No X-Webhook-Signature on request.")
			http.Error(w, "X-Webhook-Signature Missing", http.StatusBadRequest)
			return
		}

		log.Printf("X-Webhook-Signature: %q", signature)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("error reading request body: %v", err)
			http.Error(w, err.Error(), 500)
			return
		}
		defer r.Body.Close()

		sha := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(sha[:])
	
		token, err := jwt.Parse(signature, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			if token.Header["alg"] != "HS256" {
				return nil, fmt.Errorf("Unexpected signing algorithm: %v", token.Header["alg"])
			}
			return []byte(*secret), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["iss"] != *iss {
				log.Printf("Incorrect issuer: %q", claims["iss"])
				http.Error(w, "Invalid JWT issuer", http.StatusBadRequest)
				return
			}

			byteClaimed := []byte(claims["sha256"].(string))
			byteExpected := []byte(bodyHash)
			
			if 1 != subtle.ConstantTimeCompare(byteClaimed, byteExpected) {
				log.Println("Body SHA256 does not match")
				log.Printf("   JWT: %q", claims["sha256"])
				log.Printf("Actual: %q", bodyHash)
				http.Error(w, "Invalid JWT body hash", http.StatusBadRequest)
				return
			}
		} else {
			log.Printf("Token not valid: %v", err)
			http.Error(w, "Invalid JWT", http.StatusBadRequest)
			return
		}

		log.Println("Success!")
		log.Println(string(body))

		w.Write([]byte{'O','K'})
	})
	log.Printf("Starting server on %s", *address)
  log.Fatal(http.ListenAndServe(*address, nil))
}