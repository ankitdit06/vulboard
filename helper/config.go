package helper

import (
	"encoding/json"
	"fmt"
	"os"
	"vulboard/models"
)

// LoadConfig reads and parses the configuration file
func LoadConfig(filePath string) (*models.Config, error) {
	// Open the config file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	// Parse the JSON file into the Config struct
	var config models.Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}
