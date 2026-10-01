package caddypaw

import (
	"net"
	"net/http"
	"net/url"

	"go.uber.org/zap"
)

func (a *authModule) logErr(r *http.Request, reason string) {
	if a.authnConfig.FirewallURL == "" {
		return
	}

	// Strip the port from RemoteAddr (e.g. "1.2.3.4:56789") so that the
	// authn server receives a bare IP.
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	q := url.Values{
		"ip":     {ip},
		"reason": {reason},
	}

	u := a.authnConfig.FirewallURL + "/logerr?" + q.Encode()

	resp, err := httpClient.Get(u)
	if err != nil {
		a.logger.Error("firewall log err", zap.Error(err))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		a.logger.Error("firewall log err", zap.Int("status", resp.StatusCode))
	}
}
