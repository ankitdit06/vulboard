package models

import (
	"github.com/google/uuid"
	"time"
)
type Config struct {
	Fields map[string]FieldConfig `json:"fields"`
}

type FieldConfig struct {
	Path      string                 `json:"path"`
	Type      string                 `json:"type,omitempty"`      // New field for data type
	Split     string                 `json:"split,omitempty"`
	Subfields map[string]SubfieldConfig `json:"subfields,omitempty"`
}

type SubfieldConfig struct {
	SplitIndex int    `json:"split_index"`
	Delimiter  string `json:"delimiter"`
	Type       string `json:"type,omitempty"`
}

type Product struct {
	ID           uuid.UUID     `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	Name         string        `json:"name"`
	DockerImages []DockerImage `gorm:"foreignKey:ProductID" json:"docker_images"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type DockerImage struct {
	ID             uuid.UUID       `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	Tag            string          `json:"tag"`
	ProductID      uuid.UUID       `gorm:"type:uuid" json:"product_id"`
	Vulnerabilities []Vulnerability `gorm:"foreignKey:DockerImageID" json:"vulnerabilities"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type Vulnerability struct {
	ID            uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey" json:"id"`
	CVEID         string    `json:"cve_id"`
	Score         float64   `json:"score"`
	Status        string    `json:"status"` // "open" or "closed"
	DockerImageID uuid.UUID `gorm:"type:uuid" json:"docker_image_id"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
  EPSS          float64   `json:"epss"`
  Patchable     bool      `json:"patchable"` // New field for patchability status
	PatchURL      string    `json:"patch_url"` // New field for patch URL

}
