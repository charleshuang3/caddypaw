package caddypaw

import (
	"net/http"
	"net/url"

	"go.uber.org/zap"
)

func (a *authModule) logErr(r *http.Request, reason string) {
	if a.authnConfig.FirewallURL == "" {
		return
	}

	q := url.Values{
		"ip":     {r.RemoteAddr},
		"reason": {reason},
	}

	u := a.authnConfig.FirewallURL + "/logerr?" + q.Encode()

	resp, err := httpClient.Get(u)
	if err != nil {
		a.logger.Error("firewall log err", zap.Error(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		a.logger.Error("firewall log err", zap.Int("status", resp.StatusCode))
	}
}
