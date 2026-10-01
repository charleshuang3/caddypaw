package firewall

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (f *Firewall) RegisterHandlers(rg *gin.RouterGroup) {
	rg.GET("/ban", f.ban)
	rg.GET("/logerr", f.logError)
}

type firewallRequest struct {
	IP     string `form:"ip" binding:"required,ip"`
	Reason string `form:"reason" binding:"required"`
}

func (f *Firewall) ban(c *gin.Context) {
	firewallRequest := &firewallRequest{}

	if err := c.ShouldBind(firewallRequest); err != nil || net.ParseIP(firewallRequest.IP) == nil {
		c.String(http.StatusBadRequest, "Missing or invalid parameters")
		return
	}

	f.fw.BanIP(firewallRequest.IP, int(f.conf.BanMinutes), firewallRequest.Reason)
}

func (f *Firewall) logError(c *gin.Context) {
	firewallRequest := &firewallRequest{}

	if err := c.ShouldBind(firewallRequest); err != nil || net.ParseIP(firewallRequest.IP) == nil {
		c.String(http.StatusBadRequest, "Missing or invalid parameters")
		return
	}

	f.fw.LogIPError(firewallRequest.IP, firewallRequest.Reason)
}
