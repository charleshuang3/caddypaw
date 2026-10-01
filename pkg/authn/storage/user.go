package storage

import (
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func GetUserByUsernameOrEmail(db *gormw.DB, identifier string) (*models.User, error) {
	user := &models.User{}
	// Query for a user where username or email matches the identifier
	// Ensure that the column names "username" and "email" match your User model's gorm tags or actual column names.
	if err := db.Where("username = ? OR email = ?", identifier, identifier).First(&user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func GetUserByUsername(db *gormw.DB, username string) (*models.User, error) {
	user := &models.User{}
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func GetUserByEmail(db *gormw.DB, email string) (*models.User, error) {
	user := &models.User{}
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func GetUserByID(db *gormw.DB, id uint) (*models.User, error) {
	user := &models.User{}
	if err := db.Where("id = ?", id).First(&user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func CreateUser(db *gormw.DB, user *models.User) error {
	return db.Create(user).Error
}
