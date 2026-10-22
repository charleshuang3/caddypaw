package caddypaw

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/charleshuang3/caddypaw/pkg/waf"
)

// Weights of the individual signals a single request can produce. The total is
// spent against one suspicion budget per IP (see pkg/firewall), so these numbers
// decide how fast an offender is banned rather than whether they are.
//
// The model:
//
//   - one independent signal costs 1 point: a request refused by the WAF, a
//     rejected password, a broken login flow;
//   - two independent signals on the same request cost 2 points, because they
//     corroborate each other. With the default budget of 3 points
//     (forgivable.count) an ordinary violation bans on the fourth report while a
//     corroborated one bans on the second;
//   - a request that was served to an authenticated client costs 0, no matter
//     what the detect-only engine matched: tuning rules must never lock a
//     legitimate client out;
//   - a request without credentials is not reported at all. It is what every
//     browser, health check and WebDAV client sends before it knows better, so it
//     carries no evidence of intent and must not spend any budget.
const (
	// weightAuthSignal is what one rejected credential or broken login flow costs.
	// It equals the WAF weight so that any two independent signals add up to
	// exactly twice one signal.
	weightAuthSignal = waf.WeightBlocked
)

// violations collects the firewall-relevant facts of a single request.
//
// Exactly one report is emitted per request, from report(), which ServeHTTP
// defers. Reporting at the place where a violation is detected instead would let
// one request count twice: server_cookies records an invalid token, and the
// post-auth WAF pass would then report the same request again, halving the
// effective ban threshold. It is passed explicitly rather than stored on
// authModule because a module instance is shared by concurrent requests.
type violations struct {
	// wafRuleID is the rule that matched, 0 when nothing matched.
	wafRuleID int
	// wafWeight is what the match costs. It is 0 for a match on a request that
	// authenticated successfully and was served anyway (detect_only mode): such a
	// match is reported without consuming allowance. A match on an unauthenticated
	// request is a real violation and weighs waf.WeightBlocked, because the
	// request was not served.
	wafWeight int

	// authReason is the reason a credential or authentication flow was
	// rejected, empty when authentication did not fail. It keeps the
	// backend-specific wording, e.g. "callback: no auth code".
	authReason string
	// authWeight is what the authentication rejection costs.
	authWeight int
}

// reject records an authentication rejection. It keeps the first reason seen and
// the highest weight, so a later, less informative rejection cannot downgrade the
// report. It is a no-op on a nil collector so that helper functions can be called
// without one.
func (v *violations) reject(reason string, weight int) {
	if v == nil {
		return
	}
	if v.authReason == "" {
		v.authReason = reason
	}
	if weight > v.authWeight {
		v.authWeight = weight
	}
}

// recordMatch records a WAF match with the given weight.
func (v *violations) recordMatch(ruleID, weight int) {
	if v == nil {
		return
	}
	v.wafRuleID = ruleID
	v.wafWeight = weight
}

// report emits the single /logerr report for the request, if any.
//
// Both signals are reported together rather than one replacing the other: a
// request that failed authentication AND tripped a rule is the strongest
// evidence available, so its reasons are joined (the firewall keeps the most
// recent reasons for the ban log) and their weights add up. When the total weight
// is 0 the event is still logged, but as observed, so it cannot contribute to a
// ban.
func (a *authModule) report(r *http.Request, v *violations) {
	if v == nil {
		return
	}

	reasons := make([]string, 0, 2)
	weight := 0
	if v.wafRuleID != 0 {
		reasons = append(reasons, fmt.Sprintf("waf:%d", v.wafRuleID))
		weight += v.wafWeight
	}
	if v.authReason != "" {
		reasons = append(reasons, v.authReason)
		weight += v.authWeight
	}
	if len(reasons) == 0 {
		return
	}

	reason := strings.Join(reasons, " | ")
	if weight <= 0 {
		a.logObserved(r, reason)
		return
	}
	a.logErr(r, reason, weight)
}

func (a *authModule) logErr(r *http.Request, reason string, weight int) {
	if a.reporter == nil {
		return
	}
	a.reporter.Report(r, reason, weight)
}

// logObserved reports a violation that must be visible without feeding the ban
// counter.
func (a *authModule) logObserved(r *http.Request, reason string) {
	if a.reporter == nil {
		return
	}
	a.reporter.ReportObserved(r, reason)
}
