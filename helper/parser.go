package helper

import (
  "fmt"
  "strings"
  "vulboard/models"
  "vulboard/database"
  "strconv"

)

type Parser struct {
	Manager *database.VulnerabilityManager
}

func NewParser(manager *database.VulnerabilityManager) *Parser {
	return &Parser{Manager: manager}
}
func (p *Parser) ParseAndSaveJSON(data []map[string]interface{}, config models.Config) {
	for _, row := range data {
		// Get or create the product
		productName := ParseField(row, config.Fields["product"].Path).(string)
		product, err := p.Manager.GetOrCreateProduct(productName)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Get or create the Docker image
		dockerImageTag := fmt.Sprintf("%v", ParseField(row, config.Fields["dockerimage"].Path))
		dockerImage, err := p.Manager.CreateOrGetDockerImage(dockerImageTag, product.ID)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Parse and transform vulnerabilities
		rawVulnerabilities := ParseField(row, config.Fields["vulnerabilities"].Path)
		activeCVEIDs := []string{}
		if rawVulnerabilities != nil {
			vulnData := TransformField(rawVulnerabilities, config.Fields["vulnerabilities"]).([]map[string]interface{})
			activeCVEIDs, err = p.Manager.UpsertVulnerabilities(dockerImage.ID, vulnData)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
		}

		// Close old vulnerabilities scoped to the current Docker image
		if err := p.Manager.CloseOldVulnerabilities(dockerImage.ID, activeCVEIDs); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}


// ParseField retrieves a value from a nested map using a dot-separated path.
func ParseField(data map[string]interface{}, path string) interface{} {
	keys := strings.Split(path, ".") // Split path into keys
	current := data

	for i, key := range keys {
		// If the key exists in the current map, move deeper
		if value, exists := current[key]; exists {
			// If we're at the final key, return the value
			if i == len(keys)-1 {
				return value
			}

			// If it's a nested map, continue parsing
			if nested, ok := value.(map[string]interface{}); ok {
				current = nested
			} else {
				// Reached a non-map value before the end of the path
				return nil
			}
		} else {
			// Key does not exist
			return nil
		}
	}

	return nil
}
func TransformField(value interface{}, config models.FieldConfig) interface{} {
	// Return nil for empty value
	if value == nil {
		return nil
	}

	// Handle list types
	if config.Type == "list" {
		listValue, ok := value.([]interface{})
		if !ok {
			return nil // Return nil if value is not a list
		}

		var transformedList []map[string]interface{}
		for _, item := range listValue {
			itemStr, ok := item.(string)
			if !ok {
				continue
			}

			// Split the string using the defined delimiter
			parts := strings.Split(itemStr, config.Subfields["cve_id"].Delimiter)

			subfieldResult := map[string]interface{}{}
			for subfieldName, subfieldConfig := range config.Subfields {
				if subfieldConfig.SplitIndex < len(parts) {
					subValue := parts[subfieldConfig.SplitIndex]

					// Perform type conversion if required
					if subfieldConfig.Type == "float" {
						parsedValue, err := strconv.ParseFloat(subValue, 64)
						if err == nil {
							subfieldResult[subfieldName] = parsedValue
						} else {
							subfieldResult[subfieldName] = 0.0
						}
					} else {
						subfieldResult[subfieldName] = subValue
					}
				}
			}
			transformedList = append(transformedList, subfieldResult)
		}
		return transformedList
	}

	// Default behavior for non-list types
	return value
}
