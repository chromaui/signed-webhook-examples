package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

func main () {
	var (
		secret *string = flag.String("secret", "-default-secret--default-secret-", "JWT Secret")
		iss *string = flag.String("iss", "chromatic", "Issuer expected in JWT")
		address *string = flag.String("url", "http://localhost:4321/signed", "URL to request")
		badHash *bool = flag.Bool("bad-hash", false, "Tweak the body has to be incorrect")
	)
	flag.Parse()

	body := flag.Arg(0)
	if body == "" {
		log.Println("No body provided, using default.")
		body = "This Space Intentionally Left Blank"
	}

	sha := sha256.Sum256([]byte(body))
	if *badHash {
		sha[0] = sha[0] >> 4
	}
	bodyHash := hex.EncodeToString(sha[:])

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": *iss,
		"iat": time.Now().Unix(),
		"sha256": bodyHash,
	})

	tokenString, err := token.SignedString([]byte(*secret))
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBufferString(body)

	req, err := http.NewRequest(http.MethodPost, *address, buf)
	if err != nil {
		panic(err)
	}

	req.Header.Set("X-Webhook-Signature", tokenString)
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	log.Printf("Response code %v", resp.StatusCode)
	log.Println(string(responseBody))
}