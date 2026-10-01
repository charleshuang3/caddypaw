package storage

import (
	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func GetInvitationByCode(db *gormw.DB, code string) (*models.Invitation, error) {
	res := &models.Invitation{}
	if err := db.Where("code = ?", code).First(res).Error; err != nil {
		return nil, err
	} else {
		return res, nil
	}
}

func UpdateInvitation(db *gormw.DB, invitation *models.Invitation) error {
	return db.Save(invitation).Error
}

func AddInvitation(db *gormw.DB, code string, roles string) error {
	invitation := &models.Invitation{
		Code:  code,
		Roles: roles,
	}
	return db.Create(invitation).Error
}
