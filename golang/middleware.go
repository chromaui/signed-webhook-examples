package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt"
)

func withWebhookSignature(secret, issuer string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		signature := r.Header.Get("X-Webhook-Signature")
		if signature == "" {
			log.Println("❌ X-Webhook-Signature header not present")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("❌ Error reading request body: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
			return []byte(secret), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["iss"] != issuer {
				log.Printf("❌ Incorrect issuer: %q", claims["iss"])
				http.Error(w, "Invalid JWT issuer", http.StatusForbidden)
				return
			}

			if 1 != subtle.ConstantTimeCompare([]byte(claims["sha256"].(string)), []byte(bodyHash)) {
				log.Println("❌ Body SHA256 does not match")
				log.Printf("   JWT: %q", claims["sha256"])
				log.Printf("Actual: %q", bodyHash)
				http.Error(w, "Invalid JWT body hash", http.StatusForbidden)
				return
			}
		} else {
			log.Printf("❌ Could not decode JWT: %v", err)
			http.Error(w, "Invalid JWT", http.StatusForbidden)
			return
		}

		log.Println("✅ X-Webhook-Signature Valid");

		next.ServeHTTP(w, r)
	}
}