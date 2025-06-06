package caddypaw

import (
	"time"

	"github.com/google/uuid"
)

type basicAuth struct {
	password string

	user *userInfo
}

func (a *authModule) storeBasicAuth(username, password string, user *userInfo) {
	o := &basicAuth{
		password: password,
		user:     user,
	}

	expiration := time.Unix(user.Expiration, 0)
	ttl := expiration.Sub(time.Now())

	a.basicAuthCache.SetWithTTL(username, o, 1, ttl)
}

func (a *authModule) getBasicAuth(username string) (*basicAuth, bool) {
	o, ok := a.basicAuthCache.Get(username)
	if !ok {
		return nil, false
	}
	return o, true
}

const (
	defaultTTL = 10 * time.Minute
)

func (a *authModule) storeURLAndGenState(url string) string {
	state := uuid.NewString()
	a.stateCache.SetWithTTL(state, url, 1, defaultTTL)
	return state
}

func (a *authModule) getState(state string) (string, bool) {
	url, ok := a.stateCache.Get(state)
	if !ok {
		return "", false
	}
	return url, true
}

func (a *authModule) getAndDelState(state string) (string, bool) {
	url, ok := a.stateCache.Get(state)
	if !ok {
		return "", false
	}
	a.stateCache.Del(state)
	return url, true
}
