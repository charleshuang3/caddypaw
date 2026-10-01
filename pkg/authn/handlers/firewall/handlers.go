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

	f.fw.LogIPError(req.IP, req.Reason)
}
