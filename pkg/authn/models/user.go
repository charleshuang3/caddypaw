package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username       string `gorm:"uniqueIndex"`
	Name           string
	HashedPassword string
	Email          string `gorm:"uniqueIndex"`
	Roles          string // multi-roles splitted by " "
	GoogleID       string
	Picture        string
}

func (u *User) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password)) == nil
}
