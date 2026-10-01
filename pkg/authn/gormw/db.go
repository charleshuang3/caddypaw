// Package gormw provides a wrapped gorm.
package gormw

import (
	"regexp"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	zlog "github.com/rs/zerolog/log"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glog "gorm.io/gorm/logger"

	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

var (
	logger = zlog.With().Str("component", "db").Logger()
)

type DB struct {
	*gorm.DB
}

type Config struct {
	// DSN the Data Source Name.
	DSN string `yaml:"dsn"`

	// Disable automatic ping.
	DisableAutomaticPing bool `yaml:"disable_automatic_ping"`

	// Max DB open connections.
	MaxOpenConns int `yaml:"max_open_conns"`

	// Max DB idle connections.
	MaxIdleConns int `yaml:"max_idle_conns"`

	LogLevel glog.LogLevel `yaml:"log_level"`
}

func (cfg *Config) applyDefaults() {
	if cfg.DSN == "" {
		// use sqlite DB memory mode by default.
		cfg.DSN = ":memory:"
		logger.Warn().Msg("Using in-memory sqlite DB, should not be used in production")
	}

	if cfg.MaxIdleConns <= 0 {
		// golang's default.
		cfg.MaxIdleConns = 2
	}

	if cfg.LogLevel < glog.Silent || cfg.LogLevel > glog.Info {
		// INFO by default.
		cfg.LogLevel = glog.Info
	}
}

func Open(cfg *Config) (*DB, error) {
	cfg.applyDefaults()

	var dialector gorm.Dialector
	// We try to parse it as postgresql, otherwise
	// fallback to sqlite.
	if regexp.MustCompile(`^postgres(ql)?://`).MatchString(cfg.DSN) ||
		len(strings.Fields(cfg.DSN)) >= 3 {
		dialector = postgres.New(postgres.Config{
			DSN: cfg.DSN,
		})
	} else {
		dialector = sqlite.Open(cfg.DSN)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: glog.New(
			&logger,
			glog.Config{
				SlowThreshold:             100 * time.Millisecond,
				LogLevel:                  cfg.LogLevel,
				IgnoreRecordNotFoundError: false,
				ParameterizedQueries:      false,
				Colorful:                  false,
			},
		),
		PrepareStmt:          true,
		DisableAutomaticPing: cfg.DisableAutomaticPing,
	})
	if err != nil {
		return nil, err
	}

	if sqlDB, err := db.DB(); err == nil /* ignore error */ {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	return &DB{db}, nil
}

// Migrate calls gorm.DB AutoMigrate() with all models in this project.
func (db *DB) Migrate() error {
	return db.AutoMigrate(
		&models.Client{},
		&models.User{},
		&models.RefreshToken{},
		&models.Invitation{},
	)
}
