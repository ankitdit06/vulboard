package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type NVDResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			Id         string `json:"id"`
			References []struct {
				URL  string   `json:"url"`
				Tags []string `json:"tags"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// CheckIfPatchable queries the NVD API and determines if a CVE has a patch available.
func CheckIfPatchable(cveID string) (bool, string, error) {
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	// Make the HTTP GET request
	resp, err := http.Get(apiURL)
	if err != nil {
		return false, "", fmt.Errorf("failed to fetch patch information for %s: %w", cveID, err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the JSON response
	var nvdResponse NVDResponse
	if err := json.Unmarshal(body, &nvdResponse); err != nil {
		return false, "", fmt.Errorf("failed to parse NVD response: %w", err)
	}

	// Search for patch references
	for _, vuln := range nvdResponse.Vulnerabilities {
		for _, ref := range vuln.Cve.References {
			for _, tag := range ref.Tags {
				if tag == "Patch" || tag == "Vendor Advisory" {
					return true, ref.URL, nil
				}
			}
		}
	}

	// No patch found
	return false, "", nil
}
