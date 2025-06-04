package caddypaw

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"bitbucket.org/creachadair/stringset"
)

func promptForCredentials(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
}

func (a *AuthModule) checkBasicAuth(w http.ResponseWriter, r *http.Request) (int, *userInfo, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		promptForCredentials(w)
		return http.StatusUnauthorized, nil, nil
	}

	// check cache first
	if o, ok := a.getBasicAuth(username); ok {
		if o.password == password {
			return http.StatusOK, o.user, nil
		} else {
			promptForCredentials(w)
			return http.StatusUnauthorized, nil, nil
		}
	}

	// not found in cache, check on authn server

	formData := url.Values{
		"client_id":     {a.ClientID},
		"client_secret": {a.ClientSecret},
		"username":      {username},
		"password":      {password},
	}

	req, err := http.NewRequest(http.MethodPost, a.authnConfig.NonOIDCUserInfoURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			promptForCredentials(w)
			return http.StatusUnauthorized, nil, nil
		} else {
			return http.StatusInternalServerError, nil, fmt.Errorf("authn server response error %d", resp.StatusCode)
		}
	}

	u := &userInfo{}
	err = json.NewDecoder(resp.Body).Decode(u)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}

	u.roles = stringset.New(strings.Split(u.Roles, " ")...)

	a.storeBasicAuth(username, password, u)

	return http.StatusOK, u, nil
}
