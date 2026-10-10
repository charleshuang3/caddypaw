package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/test/e2e/testenv"
)

func TestStandalonePawWAF_BlockAndBan(t *testing.T) {
	c := testenv.New(t, testenv.WithWhitelist([]string{}))
	gwYAML := testenv.WriteAuthnGatewayYAML(t,
		c.AuthnURL, c.AuthnURL+"/oauth2/token", c.AuthnURL+"/user/info", c.FirewallURL)

	const caddyfileStandalone = `
{
	authn_yaml_file {authn_yaml_file}
	order paw_waf before basic_auth
	skip_install_trust
}

http://{port} {
	paw_waf {
		directives ` + "`" + `
			SecRuleEngine On
			SecRule ARGS:attack "@streq 1" "id:100,phase:2,deny,status:403"
		` + "`" + `
	}
	reverse_proxy {upstream}
}
`
	content := strings.ReplaceAll(caddyfileStandalone, "{authn_yaml_file}", gwYAML)
	c.StartCaddy(content)

	// 1. Normal request passes through to upstream.
	resp, err := http.Get(c.CaddyURL + "/hello")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NotEmpty(t, c.Upstream.Requests())

	// 2. Attack requests trigger 403 and are reported to authn /logerr.
	// Sliding window threshold is 3 forgivable errors, so the 4th request triggers a ban.
	for i := 0; i < 4; i++ {
		attackResp, attackErr := http.Get(c.CaddyURL + "/?attack=1")
		require.NoError(t, attackErr)
		require.Equal(t, http.StatusForbidden, attackResp.StatusCode)
		_ = attackResp.Body.Close()
	}

	waitForBan(t, c, "127.0.0.1")
	require.GreaterOrEqual(t, c.MemFirewall.BanCount(), 1)
	ban := c.MemFirewall.Bans()[0]
	require.Equal(t, "127.0.0.1", ban.IP)
	require.Equal(t, 10, ban.TimeoutInMinute)
}

func TestPawAuthEmbeddedWAF_BlockAndBan(t *testing.T) {
	c := testenv.New(t, testenv.WithWhitelist([]string{}))
	gwYAML := testenv.WriteAuthnGatewayYAML(t,
		c.AuthnURL, c.AuthnURL+"/oauth2/token", c.AuthnURL+"/user/info", c.FirewallURL)

	const caddyfileEmbedded = `
{
	authn_yaml_file {authn_yaml_file}
	order paw_auth before basic_auth
	skip_install_trust
}

http://{port} {
	handle /bearer/* {
		paw_auth {
			bearer_token
			token e2e-static-token
			waf {
				directives ` + "`" + `
					SecRuleEngine On
					SecRule ARGS:attack "@streq 1" "id:200,phase:2,deny,status:403"
				` + "`" + `
			}
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
			waf {
				directives ` + "`" + `
					SecRuleEngine On
					SecRule ARGS:attack "@streq 1" "id:201,phase:2,deny,status:403"
				` + "`" + `
			}
		}
		reverse_proxy {upstream}
	}
}
`
	content := strings.ReplaceAll(caddyfileEmbedded, "{authn_yaml_file}", gwYAML)
	c.StartCaddy(content)

	client := c.Client()

	// 1. Unauthenticated request with malicious payload gets 403 directly (not 302 OIDC redirect).
	for i := 0; i < 4; i++ {
		resp, err := client.Get(c.CaddyURL + "/app?attack=1")
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		_ = resp.Body.Close()
	}

	// Upstream should have received zero requests for the blocked paths.
	require.Empty(t, c.Upstream.Requests())

	// Ban should be registered in memory firewall.
	waitForBan(t, c, "127.0.0.1")
	require.GreaterOrEqual(t, c.MemFirewall.BanCount(), 1)
	ban := c.MemFirewall.Bans()[0]
	require.Equal(t, "127.0.0.1", ban.IP)
	require.Equal(t, 10, ban.TimeoutInMinute)

	// 2. Bearer route: legitimate request reaches upstream with 200 OK.
	req, _ := http.NewRequest(http.MethodGet, c.CaddyURL+"/bearer/data", nil)
	req.Header.Set("Authorization", "Bearer e2e-static-token")
	resp2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	require.NotEmpty(t, c.Upstream.Requests())

	// 3. Bearer route: request with valid token but attack payload gets 403.
	reqAttack, _ := http.NewRequest(http.MethodGet, c.CaddyURL+"/bearer/data?attack=1", nil)
	reqAttack.Header.Set("Authorization", "Bearer e2e-static-token")
	resp3, err := http.DefaultClient.Do(reqAttack)
	require.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	require.Equal(t, http.StatusForbidden, resp3.StatusCode)
}

func TestOWASPCRS_LoadingAndInspection(t *testing.T) {
	c := testenv.New(t)
	gwYAML := testenv.WriteAuthnGatewayYAML(t,
		c.AuthnURL, c.AuthnURL+"/oauth2/token", c.AuthnURL+"/user/info", c.FirewallURL)

	const caddyfileCRS = `
{
	authn_yaml_file {authn_yaml_file}
	order paw_waf before basic_auth
	skip_install_trust
}

http://{port} {
	paw_waf {
		load_owasp_crs
		directives ` + "`" + `
			Include @coraza.conf-recommended
			SecRuleEngine On
			Include @crs-setup.conf.example
			Include @owasp_crs/*.conf
		` + "`" + `
	}
	reverse_proxy {upstream}
}
`
	content := strings.ReplaceAll(caddyfileCRS, "{authn_yaml_file}", gwYAML)
	c.StartCaddy(content)

	// 1. Safe request passes.
	resp, err := http.Get(c.CaddyURL + "/?q=safe")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// 2. SQL injection payload blocked by OWASP CRS (returns 403).
	attackResp, err := http.Get(c.CaddyURL + "/?q=1%20UNION%20SELECT%201")
	require.NoError(t, err)
	defer func() { _ = attackResp.Body.Close() }()
	require.Equal(t, http.StatusForbidden, attackResp.StatusCode)
}
