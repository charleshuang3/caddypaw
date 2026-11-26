package gormw

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenInMemoryForcesSingleConnection(t *testing.T) {
	cfg := &Config{}
	db, err := Open(cfg)
	require.NoError(t, err)
	assert.Equal(t, ":memory:", cfg.DSN)
	assert.Equal(t, 1, cfg.MaxOpenConns)
	assert.Equal(t, 1, cfg.MaxIdleConns)

	sqlDB, err := db.DB.DB()
	require.NoError(t, err)
	assert.Equal(t, 1, sqlDB.Stats().MaxOpenConnections)
}
