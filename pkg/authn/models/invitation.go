package models

import "time"

type Invitation struct {
	Code      string `gorm:"primarykey"`
	Roles     string
	UpdatedAt time.Time
	UseCount  uint
}
