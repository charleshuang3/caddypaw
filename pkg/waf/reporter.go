package waf

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
		firewallURL: strings.TrimRight(firewallURL, "/"),
	}
}

// WeightBlocked is the weight of a request refused by the WAF: one point of the
// IP's suspicion budget. A request that additionally failed authentication costs
// the sum of both signals, so corroborated violations exhaust the budget — and
// therefore ban — twice as fast.
const WeightBlocked = 1

// Report logs an error for the IP associated with the given HTTP request.
//
// weight is how many points of the IP's suspicion budget the event costs; it is
// omitted from the request when it equals 1, so the authn side keeps its
// historical default.
func (r *Reporter) Report(req *http.Request, reason string, weight int) {
	r.report(req, reason, weight, true)
}

// ReportObserved logs an error for the IP associated with the given HTTP
// request without letting it consume ban allowance. Observed events never
// trigger a ban, which is what WAF detection-only mode needs.
func (r *Reporter) ReportObserved(req *http.Request, reason string) {
	r.report(req, reason, 0, false)
}

func (r *Reporter) report(req *http.Request, reason string, weight int, count bool) {
	if r == nil || r.firewallURL == "" || req == nil {
		return
	}
	ip := req.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	r.reportIP(ip, reason, weight, count)
}

func (r *Reporter) reportIP(ip string, reason string, weight int, count bool) {
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
	if !count {
		q.Set("count", "false")
	} else if weight > 1 {
		q.Set("weight", strconv.Itoa(weight))
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
