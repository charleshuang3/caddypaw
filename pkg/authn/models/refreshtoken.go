package models

import "time"

type RefreshToken struct {
	Sign      string `gorm:"primarykey"`
	UserID    uint   `gorm:"index"` // with index, user easy to find all refresh token them have
	Username  string
	Client    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Revoked   bool
	Used      bool
}
