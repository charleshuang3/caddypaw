package firewall

import (
	"log"
	"net"
	"time"

	"github.com/adrianbrad/queue"
	"golang.org/x/time/rate"

	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
)

type IFirewall interface {
	BanIP(ip string, timeoutInMinute int)
}

type ILogger interface {
	Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo)
}

type Firewall struct {
	whiteList []*ipMatcher

	ipGeo  *ipgeo.AutoUpdateMMIPGeo
	logger ILogger

	fw IFirewall

	forgivable ForgivableError
	errorCount map[string]*errorCounter

	banCh   chan ban
	countCh chan countingError
}

type ban struct {
	ip              string
	timeoutInMinute int
	reasons         []string
}

type countingError struct {
	ip     string
	reason string
	// weight is how much of the IP's allowance this event consumes. It is at
	// least 1 for counted events; reports that carry more than one independent
	// signal (a wrong password plus a WAF match) weigh more and exhaust the
	// budget sooner.
	weight int
	// observedOnly reports the event without consuming any of the IP's
	// forgivable allowance and without ever banning. Used by WAF detection-only
	// mode, which must stay visible in the logs while never causing a ban.
	observedOnly bool
}

// ForgivableError represents the suspicion budget granted to one IP within the
// given duration. Count is a budget measured in points, not in events: one
// independent signal costs 1 point, and a report that carries two corroborating
// signals costs 2. Exhausting Count points bans the IP.
type ForgivableError struct {
	Duration    time.Duration
	Count       int
	BanInMinute int
}

// DefaultWeight is the weight of one plain, uncorroborated signal.
const DefaultWeight = 1

type errorCounter struct {
	rateLimiter rate.Limiter
	reasons     *queue.Linked[string]
	bannedUntil time.Time
}

func New(whiteList []string,
	fw IFirewall,
	logger ILogger,
	ipGeo *ipgeo.AutoUpdateMMIPGeo,
	forgivable ForgivableError,
) *Firewall {
	if logger == nil {
		log.Fatalln("firewall logger is nil")
	}

	f := &Firewall{
		whiteList:  []*ipMatcher{},
		fw:         fw,
		ipGeo:      ipGeo,
		logger:     logger,
		forgivable: forgivable,
		errorCount: map[string]*errorCounter{},
		banCh:      make(chan ban),
		countCh:    make(chan countingError),
	}

	for _, it := range whiteList {
		f.whiteList = append(f.whiteList, newIPMatcher(it))
	}

	go f.loop()

	return f
}

func (s *Firewall) loop() {
	for {
		select {
		case b := <-s.banCh:
			if s.inWhitelist(b.ip) {
				// IP is whitelisted, do not log
				continue
			}
			s.doBanIP(&b)
		case c := <-s.countCh:
			if s.inWhitelist(c.ip) {
				// IP is whitelisted, do not log
				continue
			}
			if c.observedOnly {
				s.doObserveError(&c)
				continue
			}
			s.doCountError(&c)
		}
	}
}

func (s *Firewall) inWhitelist(ip string) bool {
	// The IP comes from a runtime source (an HTTP request), so it can be
	// anything. Unparseable input must not crash the process, and an IP that
	// cannot be parsed is not whitelisted: fail closed, keep counting it.
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}

	for _, it := range s.whiteList {
		if it.match(parsed) {
			return true
		}
	}
	return false
}

func (s *Firewall) doBanIP(b *ban) {
	if s.fw != nil {
		s.fw.BanIP(b.ip, b.timeoutInMinute)
	}

	var geo *ipgeo.IPGeo
	if s.ipGeo != nil {
		geo = s.ipGeo.GetIPGeo(b.ip)
	}
	jailUntil := time.Now().Add(time.Duration(b.timeoutInMinute) * time.Minute)
	s.logger.Log(b.ip, jailUntil, b.reasons, "ban", geo)
}

// BanIP imimmediately
func (s *Firewall) BanIP(ip string, timeoutInMinute int, reason string) {
	s.banCh <- ban{
		ip:              ip,
		timeoutInMinute: timeoutInMinute,
		reasons:         []string{reason},
	}
}

func (s *Firewall) doCountError(c *countingError) {
	ec, ok := s.errorCount[c.ip]
	if !ok {
		ec = &errorCounter{
			rateLimiter: *rate.NewLimiter(rate.Every(s.forgivable.Duration), s.forgivable.Count),
			reasons:     queue.NewLinked([]string{}),
		}
		s.errorCount[c.ip] = ec
	}

	if ec.bannedUntil.After(time.Now()) {
		s.logger.Log(c.ip, time.Time{}, []string{c.reason}, "banned", nil)
		return
	}

	if err := ec.reasons.Offer(c.reason); err != nil {
		log.Printf("failed to offer reason to queue: %v", err)
	}
	for ec.reasons.Size() > s.forgivable.Count {
		if _, err := ec.reasons.Get(); err != nil {
			break
		}
	}

	// A single report can never exhaust the whole budget by itself, however heavy
	// it is: weight is capped at the budget size. Banning therefore always needs at
	// least two reports within the window, so one malicious-looking request (or one
	// forged /logerr call) cannot ban an IP on its own.
	weight := c.weight
	if weight > s.forgivable.Count {
		weight = s.forgivable.Count
	}

	// AllowN is all-or-nothing: when the remaining allowance cannot cover the
	// full weight the event is not partially accounted and the IP is banned, so a
	// corroborated violation can never be discounted by leftover points.
	if ec.rateLimiter.AllowN(time.Now(), weight) {
		var geo *ipgeo.IPGeo
		if s.ipGeo != nil {
			geo = s.ipGeo.GetIPGeo(c.ip)
		}
		s.logger.Log(c.ip, time.Time{}, []string{c.reason}, "count error", geo)
		return
	}

	// record this ip is banned until time, no need to handle doCountError until then.
	ec.bannedUntil = time.Now().Add(time.Duration(s.forgivable.BanInMinute) * time.Minute)

	reasons := []string{}
	for ec.reasons.Size() > 0 {
		r, _ := ec.reasons.Get()
		reasons = append(reasons, r)
	}

	s.doBanIP(&ban{
		ip:              c.ip,
		timeoutInMinute: s.forgivable.BanInMinute,
		reasons:         reasons,
	})
}

// LogIPError counts an error happened on a request from the given ip, banning
// the ip once its allowance is exhausted.
//
// weight is the number of points the event costs; values below 1 are treated as
// DefaultWeight so that a caller cannot make a violation free by accident (use
// LogIPErrorObserved for events that must not count at all).
func (s *Firewall) LogIPError(ip string, reason string, weight int) {
	if weight < DefaultWeight {
		weight = DefaultWeight
	}
	s.countCh <- countingError{
		ip:     ip,
		reason: reason,
		weight: weight,
	}
}

// LogIPErrorObserved logs an error from the given ip without counting it against
// the forgivable allowance. It never bans, which is what detection-only WAF mode
// needs: the match stays visible in the log while the IP keeps its full budget.
func (s *Firewall) LogIPErrorObserved(ip string, reason string) {
	s.countCh <- countingError{
		ip:           ip,
		reason:       reason,
		observedOnly: true,
	}
}

// doObserveError logs an observed-only event. It neither consumes allowance nor
// bans, and it does not report "banned" for an already banned IP.
func (s *Firewall) doObserveError(c *countingError) {
	var geo *ipgeo.IPGeo
	if s.ipGeo != nil {
		geo = s.ipGeo.GetIPGeo(c.ip)
	}
	s.logger.Log(c.ip, time.Time{}, []string{c.reason}, "observed", geo)
}
