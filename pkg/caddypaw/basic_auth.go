package caddypaw

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"bitbucket.org/creachadair/stringset"
)

// reasonInvalidCredentials is the /logerr reason reported for a failed
// basic-auth attempt that presented a password. A wrong password never trips a
// WAF rule, so the WAF violation path cannot catch password brute forcing; these
// failures are counted explicitly so that repeated attempts from one IP still
// add up to a ban.
const reasonInvalidCredentials = "basic_auth: invalid credentials"

func promptForCredentials(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
}

// checkBasicAuth authenticates the request and records deliberate failures on v.
//
// A request that carries no credentials at all is not recorded: it is every
// browser's first visit, and also what health checks, uptime probes and WebDAV
// clients send before they know a protected path exists. Counting it would ban
// those clients for behaving normally. A request that presents credentials the
// authn server rejects, including an unusable Basic header, is recorded with
// reasonInvalidCredentials.
func (a *authModule) checkBasicAuth(w http.ResponseWriter, r *http.Request, v *violations) (int, *userInfo, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		// A Basic header that r.BasicAuth cannot decode is still an attempt; any
		// other scheme simply is not our business here.
		if strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "basic") {
			v.reject(reasonInvalidCredentials, weightAuthSignal)
		}
		promptForCredentials(w)
		return http.StatusUnauthorized, nil, nil
	}

	// check cache first
	if o, ok := a.getBasicAuth(username); ok {
		if o.password == password {
			return http.StatusOK, o.user, nil
		}
		v.reject(reasonInvalidCredentials, weightAuthSignal)
		promptForCredentials(w)
		return http.StatusUnauthorized, nil, nil
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			v.reject(reasonInvalidCredentials, weightAuthSignal)
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
