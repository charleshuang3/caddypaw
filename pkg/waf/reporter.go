package waf

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
)

// FirewallURLProvider provides the URL of the authn firewall endpoint.
type FirewallURLProvider interface {
	FirewallURL() string
}

// Reporter sends security violation events to the authn firewall logerr endpoint.
type Reporter struct {
	httpClient  *http.Client
	logger      *zap.Logger
	firewallURL string
}

// NewReporter creates a new Reporter with a default 5-second timeout HTTP client.
func NewReporter(logger *zap.Logger, firewallURL string) *Reporter {
	return NewReporterWithClient(logger, firewallURL, &http.Client{
		Timeout: 5 * time.Second,
	})
}

// NewReporterWithClient creates a new Reporter with a custom HTTP client.
func NewReporterWithClient(logger *zap.Logger, firewallURL string, client *http.Client) *Reporter {
	if logger == nil {
		logger = zap.NewNop()
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	return &Reporter{
		httpClient:  client,
		logger:      logger,
		firewallURL: firewallURL,
	}
}

// Report logs an error for the IP associated with the given HTTP request.
func (r *Reporter) Report(req *http.Request, reason string) {
	if r == nil || r.firewallURL == "" || req == nil {
		return
	}
	ip := req.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	r.ReportIP(ip, reason)
}

// ReportIP logs an error for a bare or host:port IP string.
func (r *Reporter) ReportIP(ip string, reason string) {
	if r == nil || r.firewallURL == "" {
		return
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	q := url.Values{
		"ip":     {ip},
		"reason": {reason},
	}
	u := r.firewallURL + "/logerr?" + q.Encode()

	resp, err := r.httpClient.Get(u)
	if err != nil {
		r.logger.Error("firewall log err", zap.Error(err), zap.String("ip", ip), zap.String("reason", reason))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		r.logger.Error("firewall log err unexpected status", zap.Int("status", resp.StatusCode), zap.String("ip", ip), zap.String("reason", reason))
	}
}
