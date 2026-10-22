package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/test/e2e/testenv"
)

const caddyfile = `{
	authn_yaml_file {authn_yaml_file}
	order paw_auth before basic_auth
	skip_install_trust
}

http://{port} {
	handle /bearer/* {
		paw_auth {
			bearer_token
			token e2e-static-token
		}
		reverse_proxy {upstream}
	}

	handle {
		paw_auth {
			server_cookies
			client_id e2e-client
			client_secret e2e-secret
			roles admin
			callback_url http://{port}/paw/callback
		}
		reverse_proxy {upstream}
	}
}
`

const afterAuthCaddyfile = `{
	authn_yaml_file {authn_yaml_file}
	order paw_auth before basic_auth
	skip_install_trust
}

http://{port} {
	paw_auth {
		bearer_token
		token e2e-static-token
		waf {
			preset default
			after_auth detect_only
		}
	}
	reverse_proxy {upstream}
}
`

// newGateway starts the full stack and returns it.
func newGateway(t *testing.T) *testenv.Cluster {
	t.Helper()
	c := testenv.New(t)
	gwYAML := testenv.WriteAuthnGatewayYAML(t,
		c.AuthnURL, c.AuthnURL+"/oauth2/token", c.AuthnURL+"/user/info", c.FirewallURL)
	content := strings.ReplaceAll(caddyfile, "{authn_yaml_file}", gwYAML)
	c.StartCaddy(content)
	return c
}

// TestOIDCFlow verifies the full OIDC authorization-code flow through the
// Caddy gateway: unauthenticated redirect -> login -> callback -> cookies ->
// upstream receives the request.
func TestOIDCFlow(t *testing.T) {
	c := newGateway(t)
	client := c.Client()

	// 1. Unauthenticated request redirects to the authn authorize endpoint.
	resp, err := client.Get(c.CaddyURL + "/app")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	require.Contains(t, loc, "/oauth2/authorize")

	// 2. Follow to the authn login page.
	resp2, err := client.Get(loc)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.Contains(t, resp2.Header.Get("Content-Type"), "text/html")

	// Extract state from the authorize URL query.
	u, err := url.Parse(loc)
	require.NoError(t, err)
	state := u.Query().Get("state")
	require.NotEmpty(t, state)

	// 3. Submit username/password login.
	form := url.Values{
		"username": {testenv.TestUsername},
		"password": {testenv.TestPassword},
		"state":    {state},
	}
	resp3, err := client.PostForm(c.AuthnURL+"/user/login", form)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	require.Equal(t, http.StatusFound, resp3.StatusCode)
	callbackLoc := resp3.Header.Get("Location")
	require.Contains(t, callbackLoc, "/paw/callback?")

	// 4. Hit the gateway callback: exchanges the code and sets cookies.
	resp4, err := client.Get(callbackLoc)
	require.NoError(t, err)
	defer func() { _ = resp4.Body.Close() }()
	require.Equal(t, http.StatusFound, resp4.StatusCode)
	require.Equal(t, "/app", resp4.Header.Get("Location"))

	// 5. Authenticated request reaches the upstream.
	resp5, err := client.Get(c.CaddyURL + "/app")
	require.NoError(t, err)
	defer func() { _ = resp5.Body.Close() }()
	require.Equal(t, http.StatusOK, resp5.StatusCode)
	require.GreaterOrEqual(t, len(c.Upstream.Requests()), 1)
}

// TestBearerToken verifies static bearer token auth through the gateway.
func TestBearerToken(t *testing.T) {
	c := newGateway(t)

	// Missing token -> 401.
	resp, err := http.Get(c.CaddyURL + "/bearer/data")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Wrong token -> 401.
	req, _ := http.NewRequest(http.MethodGet, c.CaddyURL+"/bearer/data", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// Correct token -> 200 from upstream.
	req.Header.Set("Authorization", "Bearer e2e-static-token")
	resp3, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	require.Equal(t, http.StatusOK, resp3.StatusCode)
	require.NotEmpty(t, c.Upstream.Requests())
}

// TestFirewallBan verifies the ban chain: gateway reports errors to the authn
// /logerr endpoint, the sliding window accumulates, and a ban event lands in
// the memory firewall. Localhost is whitelisted for the runner, so we call
// the firewall endpoint directly with a foreign IP, as caddypaw would.
func TestFirewallBan(t *testing.T) {
	c := testenv.New(t)

	// Below-threshold errors are counted but not banned.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(c.FirewallURL + "/logerr?ip=203.0.113.10&reason=HACKING_ERROR")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}
	require.Equal(t, 0, c.MemFirewall.BanCount(), "should not ban before threshold")

	// The (count+1)-th error in the window exhausts the rate limiter burst
	// (forgivable count = 3) and triggers a ban.
	resp, err := http.Get(c.FirewallURL + "/logerr?ip=203.0.113.10&reason=HACKING_ERROR")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	waitForBan(t, c, "203.0.113.10")
	ban := c.MemFirewall.Bans()[0]
	require.Equal(t, "203.0.113.10", ban.IP)
	require.Equal(t, 10, ban.TimeoutInMinute)

	// Direct ban endpoint also lands in the memory firewall.
	resp, err = http.Get(c.FirewallURL + "/ban?ip=198.51.100.7&reason=manual")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	waitForBanCount(t, c, 2)
	require.Equal(t, "198.51.100.7", c.MemFirewall.Bans()[1].IP)
}

// TestFirewallBanWeight verifies the suspicion budget end to end: a report that
// carries two corroborating signals spends two of the three points, so the IP is
// banned on the second such report instead of the fourth ordinary one.
func TestFirewallBanWeight(t *testing.T) {
	c := testenv.New(t)

	corroborated := "waf:949110 | basic_auth: invalid credentials"

	// The first corroborated violation spends 2 of the 3 points: not banned yet.
	resp, err := http.Get(c.FirewallURL + "/logerr?ip=203.0.113.20&reason=" +
		url.QueryEscape(corroborated) + "&weight=2")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()
	require.Equal(t, 0, c.MemFirewall.BanCount(), "a single report must never ban on its own")

	// The remaining point cannot cover a second corroborated violation, so this
	// one bans instead of being discounted.
	resp, err = http.Get(c.FirewallURL + "/logerr?ip=203.0.113.20&reason=" +
		url.QueryEscape(corroborated) + "&weight=2")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	waitForBan(t, c, "203.0.113.20")
	ban := c.MemFirewall.Bans()[0]
	require.Equal(t, "203.0.113.20", ban.IP)
	require.Equal(t, 10, ban.TimeoutInMinute)
	require.Equal(t, 1, c.MemFirewall.BanCount(), "the IP must be banned exactly once")
}

// TestAfterAuthDetectOnly exercises the documented WebDAV setup end to end: a
// real Caddy gateway with `preset default` + `after_auth detect_only`. Rules keep
// firing on authenticated traffic but nothing is blocked and nothing is counted,
// while unauthenticated probes keep their 401 and still reach the ban pipeline.
func TestAfterAuthDetectOnly(t *testing.T) {
	// The default E2E whitelist includes 127.0.0.1, which would make every
	// firewall assertion vacuous: the gateway sees all test traffic as loopback.
	c := testenv.New(t, testenv.WithWhitelist(nil))
	gwYAML := testenv.WriteAuthnGatewayYAML(t,
		c.AuthnURL, c.AuthnURL+"/oauth2/token", c.AuthnURL+"/user/info", c.FirewallURL)
	c.StartCaddy(strings.ReplaceAll(afterAuthCaddyfile, "{authn_yaml_file}", gwYAML))

	// A generic CRS rule fires on this URL (SQLi), the same request the WebDAV
	// scenario is about: legitimate authenticated clients must not be blocked.
	attackPath := "/dav/file?q=" + url.QueryEscape("1 UNION SELECT 1,2,3--")

	do := func(withToken bool) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, c.CaddyURL+attackPath, nil)
		require.NoError(t, err)
		if withToken {
			req.Header.Set("Authorization", "Bearer e2e-static-token")
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp
	}

	// Authenticated: inspected (the rule matches, see the unauthenticated loop
	// below, which bans on the same URL), reported as observed, served. Five
	// requests exceed the three-point budget, so counted matches would have
	// banned this IP well before the loop ends.
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusOK, do(true).StatusCode)
	}
	require.GreaterOrEqual(t, len(c.Upstream.Requests()), 5, "authenticated traffic must reach the upstream")
	require.Equal(t, 0, c.MemFirewall.BanCount(),
		"detect_only matches on served requests must never contribute to a ban")

	// Unauthenticated: the 401 challenge survives, but the match is counted, so
	// repeated probes still exhaust the budget (3 points, one per request).
	for i := 0; i < 4; i++ {
		require.Equal(t, http.StatusUnauthorized, do(false).StatusCode,
			"the basic-auth style challenge must not be replaced by a WAF 403")
	}
	waitForBan(t, c, "127.0.0.1")
}

// waitForBan polls until the given IP shows up in the memory firewall; the
// ban path is asynchronous (worker goroutine).
func waitForBan(t *testing.T, c *testenv.Cluster, ip string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		for _, b := range c.MemFirewall.Bans() {
			if b.IP == ip {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ip %s was never banned", ip)
}

func waitForBanCount(t *testing.T, c *testenv.Cluster, n int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c.MemFirewall.BanCount() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d bans, got %d", n, c.MemFirewall.BanCount())
}
