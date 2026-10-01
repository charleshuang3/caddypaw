package firewall

import (
	"log"
	"net"
	"strconv"
	"strings"
)

type ipMatcher struct {
	ip      net.IP
	network *net.IPNet
}

func newIPMatcher(rule string) *ipMatcher {
	ipStr, maskStr, hasMask := strings.Cut(rule, "/")
	ip := parseIP(ipStr)

	if !hasMask {
		return &ipMatcher{ip: ip}
	}

	bits := 8 * net.IPv4len
	if ip.To4() == nil {
		bits = 8 * net.IPv6len
	}

	m, err := strconv.Atoi(maskStr)
	if err != nil || m < 0 || m > bits {
		log.Fatalf("parse ip mask %q in whitelist rule %q failed", maskStr, rule)
	}

	return &ipMatcher{
		network: &net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(m, bits),
		},
	}
}

func (s *ipMatcher) match(ip net.IP) bool {
	if s.ip != nil {
		return s.ip.Equal(ip)
	}
	if s.network != nil {
		return s.network.Contains(ip)
	}
	// Not reach
	return false
}

func parseIP(s string) net.IP {
	// This is safe to crash, as the ip is from config
	ip := net.ParseIP(s)
	if ip == nil {
		log.Fatalf("whitelist entry %q is not a valid IP", s)
	}

	return ip
}
