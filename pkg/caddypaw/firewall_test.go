package caddypaw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/charleshuang3/caddypaw/pkg/caddypaw/config"
	"github.com/charleshuang3/caddypaw/pkg/waf"
)

// TestAuthModule_logErr_NilReporter verifies that calling logErr when reporter is nil does not panic.
func TestAuthModule_logErr_NilReporter(t *testing.T) {
	a := &authModule{
		logger: zap.NewNop(),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	assert.NotPanics(t, func() {
		a.logErr(req, "test reason", weightAuthSignal)
	})
}

// TestAuthModule_logErr_UnreachableFirewall verifies that a firewall endpoint
// which cannot be reached is only logged: the response used to be closed
// unconditionally, which panicked on a nil response.
func TestAuthModule_logErr_UnreachableFirewall(t *testing.T) {
	a := &authModule{
		logger:      zap.NewNop(),
		authnConfig: &config.AuthnConfig{FirewallURL: "http://127.0.0.1:1"},
		reporter:    waf.NewReporter(zap.NewNop(), "http://127.0.0.1:1"),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	assert.NotPanics(t, func() {
		a.logErr(req, "test reason", weightAuthSignal)
	})
}

// TestAuthModule_logErr_StripsPort verifies that the ip query parameter sent
// to the firewall endpoint is a bare IP without the port from RemoteAddr.
func TestAuthModule_logErr_StripsPort(t *testing.T) {
	var gotIP string
	var gotReason string
	var gotWeight string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP = r.URL.Query().Get("ip")
		gotReason = r.URL.Query().Get("reason")
		gotWeight = r.URL.Query().Get("weight")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	a := &authModule{
		logger:      zap.NewNop(),
		authnConfig: &config.AuthnConfig{FirewallURL: ts.URL},
		reporter:    waf.NewReporterWithClient(zap.NewNop(), ts.URL, ts.Client()),
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"

	a.logErr(req, "test reason", weightAuthSignal)

	assert.Equal(t, "203.0.113.5", gotIP)
	assert.Equal(t, "test reason", gotReason)
	assert.Empty(t, gotWeight, "a single-signal report omits the weight so the authn side keeps its default")
}

// TestAuthModule_report pins how the collected signals of one request are
// turned into a single report: reasons are joined, weights are summed, and a
// report whose total weight is 0 is only observed.
func TestAuthModule_report(t *testing.T) {
	type captured struct {
		reason string
		weight string
		count  string
	}

	tests := []struct {
		name        string
		v           violations
		wantReport  bool
		wantReason  string
		wantWeight  string
		wantCounted bool
	}{
		{
			name:       "nothing to report",
			v:          violations{},
			wantReport: false,
		},
		{
			name:        "WAF match only",
			v:           violations{wafRuleID: 949110, wafWeight: waf.WeightBlocked},
			wantReport:  true,
			wantReason:  "waf:949110",
			wantWeight:  "",
			wantCounted: true,
		},
		{
			// A single signal is one point, so the parameter is omitted.
			name:        "rejected password only",
			v:           violations{authReason: reasonInvalidCredentials, authWeight: weightAuthSignal},
			wantReport:  true,
			wantReason:  reasonInvalidCredentials,
			wantWeight:  "",
			wantCounted: true,
		},
		{
			// The whole point of the weights: two independent signals corroborate
			// each other, so the request spends two points and bans twice as fast.
			name: "rejected password plus WAF match",
			v: violations{
				wafRuleID:  949110,
				wafWeight:  waf.WeightBlocked,
				authReason: reasonInvalidCredentials,
				authWeight: weightAuthSignal,
			},
			wantReport:  true,
			wantReason:  "waf:949110 | " + reasonInvalidCredentials,
			wantWeight:  "2",
			wantCounted: true,
		},
		{
			name:        "match on a served authenticated request is only observed",
			v:           violations{wafRuleID: 949110, wafWeight: 0},
			wantReport:  true,
			wantReason:  "waf:949110",
			wantCounted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got captured
			reports := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reports++
				got.reason = r.URL.Query().Get("reason")
				got.weight = r.URL.Query().Get("weight")
				got.count = r.URL.Query().Get("count")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(ts.Close)

			a := &authModule{
				logger:   zap.NewNop(),
				reporter: waf.NewReporterWithClient(zap.NewNop(), ts.URL, ts.Client()),
			}
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "203.0.113.9:1234"

			v := tt.v
			a.report(req, &v)

			if !tt.wantReport {
				assert.Equal(t, 0, reports)
				return
			}
			require.Equal(t, 1, reports, "one request must produce at most one report")
			assert.Equal(t, tt.wantReason, got.reason)
			assert.Equal(t, tt.wantWeight, got.weight)
			if tt.wantCounted {
				assert.Empty(t, got.count)
			} else {
				assert.Equal(t, "false", got.count)
			}
		})
	}
}
