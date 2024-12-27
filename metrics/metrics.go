package metrics

import (
	"log"

	"gorm.io/gorm"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	VulnerabilityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "vulnerability_score",
			Help: "Vulnerability score by product, Docker image, CVE ID, status,Patchable, PatchURL, LastUpdated, Created On,EPSS",
		},
		[]string{"product", "dockerimage", "cve_id", "status", "Patchable", "PatchURL", "UpdatedAt", "CreatedAt", "Epss"},
	)
)

type VulnerabilityMetric struct {
	Product     string  `json:"product"`
	Dockerimage string  `json:"dockerimage"`
	CVEID       string  `json:"cve_id"`
	Status      string  `json:"status"`
	Score       float64 `json:"score"`
	Patchable   string  `json:"patchable"`
	PatchURL    string  `json:"patchurl"`
	UpdatedAt   string  `json:"Updated_at"`
	CreatedAt   string  `json:"created_at"`
	Epss        string  `json:"epss"`
}

func init() {
	// Register the metric with Prometheus
	prometheus.MustRegister(VulnerabilityGauge)
}

// FetchVulnerabilityMetrics reads data from the database
func FetchVulnerabilityMetrics(db *gorm.DB) ([]VulnerabilityMetric, error) {
	var metrics []VulnerabilityMetric

	// Join tables to fetch required data
	err := db.Table("vulnerabilities").
		Select("products.name AS product, docker_images.tag AS dockerimage, vulnerabilities.cve_id, vulnerabilities.status, vulnerabilities.score,vulnerabilities.patchable,vulnerabilities.patch_url,vulnerabilities.updated_at,vulnerabilities.created_at,vulnerabilities.epss").
		Joins("JOIN docker_images ON vulnerabilities.docker_image_id = docker_images.id").
		Joins("JOIN products ON docker_images.product_id = products.id").
		Find(&metrics).Error

	if err != nil {
		return nil, err
	}

	return metrics, nil
}

// UpdateMetrics reads data from DB and updates Prometheus metrics
func UpdateMetrics(db *gorm.DB) {
	// Clear existing metrics
	VulnerabilityGauge.Reset()

	// Fetch metrics data from the database
	metrics, err := FetchVulnerabilityMetrics(db)
	if err != nil {
		log.Printf("Error fetching vulnerability metrics: %v\n", err)
		return
	}

	// Populate Prometheus metrics
	for _, metric := range metrics {

		VulnerabilityGauge.WithLabelValues(metric.Product, metric.Dockerimage, metric.CVEID, metric.Status, metric.Patchable, metric.PatchURL, metric.UpdatedAt, metric.CreatedAt, metric.Epss).Set(metric.Score)
	}
}
