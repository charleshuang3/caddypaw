package caddypaw

import "time"

type basicAuth struct {
	password string

	user *userInfo
}

func (a *AuthModule) storeBasicAuth(username, password string, user *userInfo) {
	o := &basicAuth{
		password: password,
		user:     user,
	}

	expiration := time.Unix(user.Expiration, 0)
	ttl := expiration.Sub(time.Now())

	a.basicAuthCache.SetWithTTL(username, o, 1, ttl)
}

func (a *AuthModule) getBasicAuth(username string) (*basicAuth, bool) {
	o, ok := a.basicAuthCache.Get(username)
	if !ok {
		return nil, false
	}
	return o, true
}
