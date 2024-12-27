package database

import (
	"errors"
	"fmt"
	"log"
	"time"
	"vulboard/models"
	"vulboard/services"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase(dsn string) *Database {

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Enable UUID extension for PostgreSQL
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")

	// Auto-migrate schema
	err = db.AutoMigrate(&models.Product{}, &models.DockerImage{}, &models.Vulnerability{})
	if err != nil {
		log.Fatalf("Failed to migrate database schema: %v", err)
	}

	return &Database{DB: db}
}

type VulnerabilityManager struct {
	DB *gorm.DB
}

func NewVulnerabilityManager(db *gorm.DB) *VulnerabilityManager {
	return &VulnerabilityManager{DB: db}
}

func (vm *VulnerabilityManager) GetOrCreateProduct(productName string) (*models.Product, error) {
	var product models.Product
	if err := vm.DB.FirstOrCreate(&product, models.Product{Name: productName}).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch/create product: %w", err)
	}
	return &product, nil
}

func (vm *VulnerabilityManager) CreateOrGetDockerImage(tag string, productID uuid.UUID) (*models.DockerImage, error) {
	var dockerImage models.DockerImage
	// Check if a Docker image with the same tag and product ID already exists
	if err := vm.DB.Where("tag = ? AND product_id = ?", tag, productID).First(&dockerImage).Error; err == nil {
		// Docker image exists
		return &dockerImage, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		// Return error if it's not a "record not found" error
		return nil, fmt.Errorf("failed to check existing docker image: %w", err)
	}

	// Create a new Docker image if it doesn't exist
	dockerImage = models.DockerImage{
		Tag:       tag,
		ProductID: productID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := vm.DB.Create(&dockerImage).Error; err != nil {
		return nil, fmt.Errorf("failed to create docker image: %w", err)
	}

	return &dockerImage, nil
}

func (vm *VulnerabilityManager) GetHistoricalVulnerabilities(productID uuid.UUID) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability
	err := vm.DB.Joins("JOIN docker_images ON vulnerabilities.docker_image_id = docker_images.id").
		Where("docker_images.product_id = ?", productID).
		Find(&vulnerabilities).Error
	if err != nil {
		return nil, fmt.Errorf("failed to fetch historical vulnerabilities: %w", err)
	}
	return vulnerabilities, nil
}

func (vm *VulnerabilityManager) UpsertVulnerabilities(dockerImageID uuid.UUID, vulnData []map[string]interface{}) ([]string, error) {
	var cveIDs []string
	for _, v := range vulnData {
		cveID := fmt.Sprintf("%v", v["cve_id"])
		score := v["score"].(float64)

		// Query EPSS value dynamically
		epss, err := services.GetEPSS(cveID)
		if err != nil {
			fmt.Printf("Warning: Unable to fetch EPSS for %s. Defaulting to 0.0. Error: %v\n", cveID, err)
			epss = 0.0 // Use default value if API call fails
		}

		// Check if the vulnerability is patchable
		patchable, patchURL, err := services.CheckIfPatchable(cveID)
		if err != nil {
			fmt.Printf("Warning: Unable to check patch availability for %s. Error: %v\n", cveID, err)
		}

		var vuln models.Vulnerability
		if err := vm.DB.FirstOrCreate(&vuln, models.Vulnerability{CVEID: cveID, DockerImageID: dockerImageID}).Error; err != nil {
			return nil, fmt.Errorf("failed to fetch/create vulnerability: %w", err)
		}

		vuln.Score = score
		vuln.EPSS = epss
		vuln.Patchable = patchable
		vuln.PatchURL = patchURL
		vuln.Status = "open"
		vuln.UpdatedAt = time.Now()
		if err := vm.DB.Save(&vuln).Error; err != nil {
			return nil, fmt.Errorf("failed to update vulnerability: %w", err)
		}

		cveIDs = append(cveIDs, cveID)
	}
	return cveIDs, nil
}

func (vm *VulnerabilityManager) CloseOldVulnerabilities(dockerImageID uuid.UUID, activeCVEIDs []string) error {
	var vulnerabilities []models.Vulnerability

	// Fetch vulnerabilities for the specific Docker image
	if err := vm.DB.Where("docker_image_id = ?", dockerImageID).Find(&vulnerabilities).Error; err != nil {
		return fmt.Errorf("failed to fetch vulnerabilities for image %s: %w", dockerImageID, err)
	}

	for _, vuln := range vulnerabilities {
		if !contains(activeCVEIDs, vuln.CVEID) {
			vuln.Status = "closed"
			vuln.UpdatedAt = time.Now()
			if err := vm.DB.Save(&vuln).Error; err != nil {
				return fmt.Errorf("failed to close vulnerability %s: %w", vuln.CVEID, err)
			}
		}
	}
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
