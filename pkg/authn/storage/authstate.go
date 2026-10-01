package storage

import (
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/rs/zerolog/log"
)

const (
	authStateTTL  = 10 * time.Minute
	maxAuthStates = 10000
)

type AuthStateStorage struct {
	cache *ristretto.Cache[string, *AuthState]
}

type AuthState struct {
	ClientID    string
	RedirectURI string
	Scopes      []string
}

func NewAuthStateStorage() *AuthStateStorage {
	c, err := ristretto.NewCache(&ristretto.Config[string, *AuthState]{
		NumCounters: maxAuthStates,
		MaxCost:     maxAuthStates,
		BufferItems: 64,
	})

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create auth state storage")
	}

	return &AuthStateStorage{
		cache: c,
	}
}

func (s *AuthStateStorage) Get(key string) (*AuthState, bool) {
	return s.cache.Get(key)
}

func (s *AuthStateStorage) Set(key string, value *AuthState) {
	s.cache.SetWithTTL(key, value, 1, authStateTTL)
	s.cache.Wait()
}

func (s *AuthStateStorage) Delete(key string) {
	s.cache.Del(key)
	s.cache.Wait()
}
