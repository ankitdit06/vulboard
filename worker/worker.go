package worker

import (
	"encoding/json"
	"fmt"
	"vulboard/database"
	"vulboard/helper"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"
)

func StartWorker(nc *nats.Conn, db *gorm.DB) {
	// Subject to subscribe to
	subject := "vuln.data"

	// Subscribe to subject
	_, err := nc.Subscribe(subject, func(msg *nats.Msg) {

		//var inputData string
		var inputJSON []map[string]interface{}
		err := json.Unmarshal(msg.Data, &inputJSON)

		if err != nil {
			fmt.Printf("Failed to deserialize event: %v\n", err)

		}

		//	json.Unmarshal([]byte(inputData), &inputJSON)
		// Path to the configuration file
		configFilePath := "config.json"

		// Load the configuration
		cfg, err := helper.LoadConfig(configFilePath)
		if err != nil {
			fmt.Printf("Error loading config: %v\n", err)
			return
		}
		manager := database.NewVulnerabilityManager(db)
		parser := helper.NewParser(manager)
		parser.ParseAndSaveJSON(inputJSON, *cfg)

	})
	if err != nil {
		fmt.Printf("Failed to get vuln: %v\n", err)

	}
}
