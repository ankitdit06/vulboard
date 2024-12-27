package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
  "strconv"
)

type EPSSResponse struct {
	Data []struct {
		CVE  string  `json:"cve"`
		EPSS string `json:"epss"`
	} `json:"data"`
}

// GetEPSS fetches the EPSS value for a given CVE ID using the API.
func GetEPSS(cveID string) (float64, error) {
	apiURL := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID)

	// Make the HTTP GET request
	resp, err := http.Get(apiURL)
	if err != nil {
		return 0.0, fmt.Errorf("failed to fetch EPSS for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0.0, fmt.Errorf("failed to read response body: %w", err)
	}


	// Parse the JSON response
	var epssResponse EPSSResponse
	if err := json.Unmarshal(body, &epssResponse); err != nil {
		return 0.0, fmt.Errorf("failed to parse EPSS response: %w", err)
	}

	// Extract the EPSS value from the response
	if len(epssResponse.Data) > 0 {
    epssStr := epssResponse.Data[0].EPSS
		epss, err := strconv.ParseFloat(epssStr, 64)
		if err != nil {
			return 0.0, fmt.Errorf("failed to convert EPSS value %s to float: %w", epssStr, err)
		}
		return epss, nil
	}

	// Return default value if no data is available
	return 0.0, nil
}
