package api

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/nats-io/nats.go"
)

type VulnerabilityInput struct {
	Product         string   `json:"product"`
	DockerImage     string   `json:"dockerimage"`
	Vulnerabilities []string `json:"vulnerabilities"`
}

func HandleVulnerabilities(nc *nats.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the request method is POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read request body: %v", err), http.StatusInternalServerError)
			return
		}
		defer r.Body.Close() // Always close the body after reading
		// Publish to NATS subject
		subject := "vuln.data"
		err = nc.Publish(subject, body)
		if err != nil {
			log.Fatalf("Failed to publish to NATS: %v", err)
		}

		log.Printf("Published message to subject '%s'\n", subject)

		// Return success response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Vulnerabilities processed successfully"))
	}
}
