package storage

import (
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/rs/zerolog/log"
)

const (
	authCodeTTL  = 5 * time.Minute
	maxAuthCodes = 10000
)

type AuthCodeStorage struct {
	cache *ristretto.Cache[string, *AuthCode]
}

type AuthCode struct {
	UserID      uint
	ClientID    string
	Scopes      []string
	RedirectURI string
}

func NewAuthCodeStorage() *AuthCodeStorage {
	c, err := ristretto.NewCache(&ristretto.Config[string, *AuthCode]{
		NumCounters: maxAuthCodes,
		MaxCost:     maxAuthCodes,
		BufferItems: 64,
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create auth code storage")
	}

	return &AuthCodeStorage{
		cache: c,
	}
}

func (s *AuthCodeStorage) Get(key string) (*AuthCode, bool) {
	return s.cache.Get(key)
}

func (s *AuthCodeStorage) Set(key string, value *AuthCode) {
	s.cache.SetWithTTL(key, value, 1, authCodeTTL)
	s.cache.Wait()
}

func (s *AuthCodeStorage) Delete(key string) {
	s.cache.Del(key)
	s.cache.Wait()
}
