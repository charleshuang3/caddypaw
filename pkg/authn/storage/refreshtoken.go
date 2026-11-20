package storage

import (
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

var (
	logger = log.With().Str("component", "storage").Logger()
)

func AddRefreshToken(db *gormw.DB, refreshToken *models.RefreshToken) error {
	return db.Create(refreshToken).Error
}

func GetRefreshTokenBySign(db *gormw.DB, sign string) (*models.RefreshToken, error) {
	o := &models.RefreshToken{}
	err := db.Where("sign = ?", sign).First(&o).Error
	return o, err
}

// MarkRefreshTokenUsed marks the token as used and records the first use time.
// It is a no-op when the token was already marked, so concurrent exchanges keep
// the original used_at and the grace period is not extended.
func MarkRefreshTokenUsed(db *gormw.DB, refreshToken *models.RefreshToken) error {
	now := time.Now()
	res := db.Model(&models.RefreshToken{}).
		Where("sign = ? AND used = ?", refreshToken.Sign, false).
		Updates(map[string]any{"used": true, "used_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected > 0 {
		refreshToken.Used = true
		refreshToken.UsedAt = &now
	}
	return nil
}

// Refresh token will exists in database forever if not register a cleaner.
func RegisterRefreshTokensCleaner(scheduler gocron.Scheduler, db *gormw.DB) {
	_, _ = scheduler.NewJob(
		gocron.CronJob(
			// 4am Daily
			"0 4 * * *",
			false,
		),
		gocron.NewTask(
			func() {
				logger.Info().Msg("Cleaning up expired refresh tokens")
				yesterday := time.Now().AddDate(0, 0, -1)
				db.Where("expires_at < ?", yesterday).Delete(&models.RefreshToken{})
			},
		),
	)
}
