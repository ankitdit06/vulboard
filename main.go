package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"vulboard/api"
	"vulboard/database"
	"vulboard/metrics"
	"vulboard/worker"

	"github.com/nats-io/nats.go"

	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Helper function to get an environment variable with a default value
func Getenv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Tracks readiness status
var ready atomic.Value

func main() {
	// Connect to RabbitMQ
	// Retrieve the value of an environment variable
	dbHost := Getenv("POSTGRES_HOST", "localhost")
	dbUser := Getenv("POSTGRES_USER", "secureg")
	dbPassword := Getenv("POSTGRES_PASSWORD", "secureg")
	dbName := Getenv("POSTGRES_DB", "vulboard")

	// Print the variables (useful for debugging)
	dbstring := fmt.Sprintf("host= %s user=%s password=%s dbname=%s port=5432 sslmode=disable", dbHost, dbUser, dbPassword, dbName)

	// Check if a variable is set
	if dbHost == "" || dbUser == "" || dbPassword == "" || dbName == "" {
		fmt.Println("one or more postgres parameters are missing")
		os.Exit(1)
	}

	natshost := Getenv("NATS_HOST", "localhost")
	// Check if a variable is set
	if natshost == "" {
		fmt.Println("one or more rabbitmq parameters are missing")
		os.Exit(1)
	}

	// Initialize readiness to false
	ready.Store(false)

	// Start a background process to simulate readiness after some initialization time
	go func() {
		log.Println("Starting initialization...")
		time.Sleep(10 * time.Second) // Simulate initialization delay
		ready.Store(true)            // Mark as ready
		log.Println("Application is now ready!")
	}()

	// Liveness Probe: Always returns 200 if the app is running
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	// Readiness Probe: Returns 200 if the app is ready, otherwise 503
	http.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if ready.Load().(bool) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "Not Ready")
		}
	})

	natsURL := fmt.Sprintf("nats://%s:4222/", natshost)
	// Use the Kubernetes service DNS name for NATS
	//natsURL := "nats://nats:4222"

	// Connect to NATS
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", natsURL, err)
	} else {
		log.Println("Connected to NATS Server")
	}
	defer nc.Close()

	db := database.NewDatabase(dbstring).DB

	// Start the  worker
	go worker.StartWorker(nc, db)

	// Start the HTTP server
	fmt.Println("Server running on :8080")
	// Register API endpoints
	http.HandleFunc("/api/v1/vulnerabilities", api.HandleVulnerabilities(nc))

	// Periodically update metrics from the database
	go func() {
		for {
			metrics.UpdateMetrics(db)
			// Update metrics every 1 minute
			time.Sleep(1 * time.Minute)
		}
	}()

	// Expose metrics at /metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}
