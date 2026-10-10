package caddypaw

import (
	"net/http"
)

func (a *authModule) logErr(r *http.Request, reason string) {
	if a.reporter == nil {
		return
	}
	a.reporter.Report(r, reason)
}
