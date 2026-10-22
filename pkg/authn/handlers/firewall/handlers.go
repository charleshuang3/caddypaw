package firewall

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (f *Firewall) RegisterHandlers(rg *gin.RouterGroup) {
	rg.GET("/ban", f.ban)
	rg.GET("/logerr", f.logError)
}

type firewallRequest struct {
	IP     string `form:"ip" binding:"ip"`
	Reason string `form:"reason" binding:"required"`
	// Weight is how much of the IP's suspicion budget the event consumes. It
	// defaults to 1 so that a gateway which does not send it keeps the historical
	// "one event, one point" behaviour. A report that carries two corroborating
	// signals (a wrong password AND a WAF match) sends 2. The upper bound is the
	// heaviest weight a single request can produce, which keeps one /logerr call
	// from spending an arbitrarily large share of the budget.
	Weight *int `form:"weight" binding:"omitempty,min=1,max=2"`
	// Count is false when the reporter only wants the event logged. Observed
	// events never consume the IP's forgivable allowance and never ban, which is
	// what WAF detection-only mode needs.
	Count *bool `form:"count"`
}

// counts reports whether the event must consume ban allowance. Omitting the
// parameter keeps the historical behaviour (it counts).
func (r *firewallRequest) counts() bool {
	return r.Count == nil || *r.Count
}

// eventWeight returns the validated weight of the event.
func (r *firewallRequest) eventWeight() int {
	if r.Weight == nil {
		return 1
	}
	return *r.Weight
}

// bindRequest binds and validates the query parameters shared by /ban and
// /logerr. On failure it answers 400 and returns nil.
func bindRequest(c *gin.Context) *firewallRequest {
	req := &firewallRequest{}
	if err := c.ShouldBind(req); err != nil {
		c.String(http.StatusBadRequest, "Missing or invalid parameters")
		return nil
	}

	return req
}

func (f *Firewall) ban(c *gin.Context) {
	req := bindRequest(c)
	if req == nil {
		return
	}

	f.fw.BanIP(req.IP, int(f.conf.BanMinutes), req.Reason)
}

func (f *Firewall) logError(c *gin.Context) {
	req := bindRequest(c)
	if req == nil {
		return
	}

	if !req.counts() {
		f.fw.LogIPErrorObserved(req.IP, req.Reason)
		return
	}

	f.fw.LogIPError(req.IP, req.Reason, req.eventWeight())
}
