package zerolog

import (
	"encoding/json"
	"time"

	zlog "github.com/rs/zerolog"

	"github.com/charleshuang3/caddypaw/pkg/firewall"
	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
)

var (
	_ firewall.ILogger      = (*ZeroLog)(nil)
	_ firewall.IEventLogger = (*ZeroLog)(nil)
)

type ZeroLog struct {
	logger zlog.Logger
	level  zlog.Level
}

func New(logger zlog.Logger, level zlog.Level, service string) *ZeroLog {
	logger = logger.With().Str("service", service).Logger()
	return &ZeroLog{
		logger: logger,
		level:  level,
	}
}

func (z *ZeroLog) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	z.LogEvent(firewall.Event{
		IP:        ip,
		JailUntil: jailUntil,
		Reasons:   reasons,
		Action:    action,
		Geo:       geo,
	})
}

func (z *ZeroLog) LogEvent(ev firewall.Event) {
	var b []byte
	if ev.Geo != nil {
		b, _ = json.Marshal(ev.Geo)
	}

	e := z.logger.WithLevel(z.level).
		Str("ip", ev.IP).
		Time("jail_until", ev.JailUntil).
		Strs("reasons", ev.Reasons).
		Str("action", ev.Action)

	if ev.Meta.Host != "" {
		e.Str("host", ev.Meta.Host)
	}
	if ev.Meta.Method != "" {
		e.Str("method", ev.Meta.Method)
	}
	if ev.Meta.Path != "" {
		e.Str("path", ev.Meta.Path)
	}

	if b != nil {
		e.RawJSON("geo", b)
	}

	e.Msg("") // emit the log
}
