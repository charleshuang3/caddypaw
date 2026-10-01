package storage

import (
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func GetClientByID(db *gormw.DB, id string) (*models.Client, error) {
	client := &models.Client{}

	res := db.Where("client_id = ?", id).First(client)
	if res.Error != nil {
		return nil, res.Error
	}

	return client, nil
}
