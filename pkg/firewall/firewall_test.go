package firewall

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
)

// MockIFirewall is a mock implementation of IFirewall for testing.
type MockIFirewall struct {
	BannedIPs []string
}

func (m *MockIFirewall) BanIP(ip string, timeoutInMinute int) {
	m.BannedIPs = append(m.BannedIPs, ip)
}

// MockILogger is a mock implementation of ILogger for testing.
type MockILogger struct {
	Logs []LogEntry
	Wg   sync.WaitGroup
}

type LogEntry struct {
	IP        string
	JailUntil time.Time
	Reasons   []string
	Action    string
	Geo       *ipgeo.IPGeo
}

func (m *MockILogger) Log(ip string, jailUntil time.Time, reasons []string, action string, geo *ipgeo.IPGeo) {
	m.Logs = append(m.Logs, LogEntry{
		IP:        ip,
		JailUntil: jailUntil,
		Reasons:   reasons,
		Action:    action,
		Geo:       geo,
	})
	m.Wg.Done()
}

func TestBanIP(t *testing.T) {
	tests := []struct {
		name            string
		ip              string
		timeoutInMinute int
		reason          string
		whiteList       []string
		expectedBanned  bool
		expectedLog     *LogEntry // Changed to pointer
	}{
		{
			name:            "Ban non-whitelisted IP",
			ip:              "192.168.1.1",
			timeoutInMinute: 10,
			reason:          "Too many failed logins",
			whiteList:       []string{},
			expectedBanned:  true,
			expectedLog: &LogEntry{ // Changed to pointer
				IP:      "192.168.1.1",
				Reasons: []string{"Too many failed logins"},
				Action:  "ban",
				Geo:     nil, // Mock IPGeo is nil
			},
		},
		{
			name:            "Do not ban whitelisted IP",
			ip:              "192.168.1.2",
			timeoutInMinute: 10,
			reason:          "Too many failed logins",
			whiteList:       []string{"192.168.1.2"},
			expectedBanned:  false,
			// expectedLog is intentionally omitted as no log is expected.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFW := &MockIFirewall{}
			mockLogger := &MockILogger{}
			fw := New(tt.whiteList, mockFW, mockLogger, nil, ForgivableError{}) // ipGeo and forgivableError are not used in BanIP directly

			if tt.expectedLog != nil { // If we expect a log
				mockLogger.Wg.Add(1)
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				mockLogger.Wg.Wait()

				assert.Len(t, mockLogger.Logs, 1)
				logEntry := mockLogger.Logs[0]
				assert.Equal(t, tt.expectedLog.IP, logEntry.IP)
				assert.Equal(t, tt.expectedLog.Reasons, logEntry.Reasons)
				assert.Equal(t, tt.expectedLog.Action, logEntry.Action)
				// Geo and JailUntil are not checked precisely here
			} else { // If we do not expect a log (whitelisted IP or other no-log scenarios)
				fw.BanIP(tt.ip, tt.timeoutInMinute, tt.reason)
				assert.Empty(t, mockLogger.Logs)
			}

			if tt.expectedBanned {
				assert.Equal(t, []string{tt.ip}, mockFW.BannedIPs)
			} else {
				// For "Do not ban whitelisted IP", BannedIPs should be empty.
				// For other potential future test cases that might not ban but also not be whitelisted,
				// NotContains might be more appropriate if BannedIPs could have other entries.
				// Given current tests, Empty is fine for the whitelisted case.
				// Sticking to NotContains as it was, which is also safe.
				assert.NotContains(t, mockFW.BannedIPs, tt.ip)
			}
		})
	}
}

func TestLogIPError(t *testing.T) {
	tests := []struct {
		name              string
		ip                string
		reason            string
		forgivable        ForgivableError
		errorCount        int // Number of times to call LogIPError
		whiteList         []string
		expectedBanned    bool
		expectedLogAction string
		expectLog         bool
	}{
		{
			name:              "Log error at threshold",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        2,
			whiteList:         []string{},
			expectedBanned:    false,
			expectedLogAction: "count error",
			expectLog:         true,
		},
		{
			name:              "Log error above threshold, should ban",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        3,
			whiteList:         []string{},
			expectedBanned:    true,
			expectedLogAction: "ban",
			expectLog:         true,
		},
		{
			name:              "Log error above threshold + 1, should not be double ban",
			ip:                "192.168.1.1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        4,
			whiteList:         []string{},
			expectedBanned:    true,
			expectedLogAction: "banned",
			expectLog:         true,
		},
		{
			name:              "Log error for whitelisted IP",
			ip:                "192.168.1.2",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 3, BanInMinute: 5},
			errorCount:        5, // Should not matter for whitelisted
			whiteList:         []string{"192.168.1.2"},
			expectedBanned:    false,
			expectedLogAction: "whitelisted",
			expectLog:         false,
		},
		{
			// Fail closed: an IP that cannot be parsed is not whitelisted, so it
			// is still counted and banned instead of crashing the process.
			name:              "Log error with unparseable IP, must not crash",
			ip:                "192.168.1.1:54321", // host:port, unparseable as IP
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        3,
			whiteList:         []string{"192.168.1.0/24"},
			expectedBanned:    true,
			expectedLogAction: "ban",
			expectLog:         true,
		},
		{
			name:              "Log error with IPv6 IP, must not crash",
			ip:                "2001:db8::1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5},
			errorCount:        2,
			whiteList:         []string{"192.168.1.0/24"},
			expectedBanned:    false,
			expectedLogAction: "count error",
			expectLog:         true,
		},
		{
			name:              "Log error for whitelisted IPv6 IP",
			ip:                "2001:db8::1",
			reason:            "Invalid password",
			forgivable:        ForgivableError{Duration: time.Minute, Count: 3, BanInMinute: 5},
			errorCount:        5,
			whiteList:         []string{"2001:db8::/32"},
			expectedBanned:    false,
			expectedLogAction: "whitelisted",
			expectLog:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockFW := &MockIFirewall{}
			mockLogger := &MockILogger{}
			fw := New(tt.whiteList, mockFW, mockLogger, nil, tt.forgivable) // ipGeo is not used in LogIPError directly

			if tt.expectLog { // Use the new field from the test struct
				mockLogger.Wg.Add(tt.errorCount)
			}

			for i := 0; i < tt.errorCount; i++ {
				fw.LogIPError(tt.ip, tt.reason, DefaultWeight)
			}

			if tt.expectLog { // Use the new field from the test struct
				mockLogger.Wg.Wait()
				assert.Len(t, mockLogger.Logs, tt.errorCount)
				assert.NotEmpty(t, mockLogger.Logs) // Should be true if errorCount > 0
				lastLogEntry := mockLogger.Logs[len(mockLogger.Logs)-1]
				assert.Equal(t, tt.expectedLogAction, lastLogEntry.Action)
			} else {
				assert.Empty(t, mockLogger.Logs)
			}

			if tt.expectedBanned {
				assert.Equal(t, []string{tt.ip}, mockFW.BannedIPs)
			} else {
				assert.NotContains(t, mockFW.BannedIPs, tt.ip)
			}
		})
	}
}

// TestLogIPErrorObserved makes sure an observed event never consumes allowance
// and never bans, no matter how many arrive. This is what WAF detection-only
// mode relies on: it must stay visible in the log without blocking clients.
func TestLogIPErrorObserved(t *testing.T) {
	mockFW := &MockIFirewall{}
	mockLogger := &MockILogger{}
	forgivable := ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5}
	fw := New([]string{}, mockFW, mockLogger, nil, forgivable)

	const observed = 10
	mockLogger.Wg.Add(observed)
	for i := 0; i < observed; i++ {
		fw.LogIPErrorObserved("192.168.1.50", "waf:6001")
	}
	mockLogger.Wg.Wait()

	assert.Empty(t, mockFW.BannedIPs, "observed events must never ban")
	require.Len(t, mockLogger.Logs, observed)
	for _, entry := range mockLogger.Logs {
		assert.Equal(t, "observed", entry.Action)
		assert.Equal(t, []string{"waf:6001"}, entry.Reasons)
	}

	// Observed events must not have eaten the allowance: the IP still needs the
	// full Count+1 counted errors before it is banned.
	mockLogger.Wg.Add(3)
	for i := 0; i < 3; i++ {
		fw.LogIPError("192.168.1.50", "Invalid password", DefaultWeight)
	}
	mockLogger.Wg.Wait()

	assert.Equal(t, []string{"192.168.1.50"}, mockFW.BannedIPs,
		"counted errors must still ban on schedule")
}

// TestLogIPErrorWeight pins the budget semantics: Count is a number of points,
// and a report may spend two of them when two independent signals corroborate
// each other. A corroborated violation must therefore be banned in half the
// reports an ordinary one needs.
func TestLogIPErrorWeight(t *testing.T) {
	const ip = "192.168.1.60"

	t.Run("corroborated violation bans on the second report", func(t *testing.T) {
		mockFW := &MockIFirewall{}
		mockLogger := &MockILogger{}
		forgivable := ForgivableError{Duration: time.Minute, Count: 3, BanInMinute: 5}
		fw := New([]string{}, mockFW, mockLogger, nil, forgivable)

		// A wrong password plus a WAF match: 1 + 1 = 2 of the 3 points.
		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "waf:949110 | basic_auth: invalid credentials", 2)
		mockLogger.Wg.Wait()

		require.Len(t, mockLogger.Logs, 1)
		assert.Equal(t, "count error", mockLogger.Logs[0].Action)
		assert.Empty(t, mockFW.BannedIPs, "one report must not ban on its own")

		// The second corroborated report cannot fit in the remaining point, so it
		// bans: two reports instead of the four an ordinary violation needs.
		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "waf:949110 | basic_auth: invalid credentials", 2)
		mockLogger.Wg.Wait()

		assert.Equal(t, []string{ip}, mockFW.BannedIPs)
		last := mockLogger.Logs[len(mockLogger.Logs)-1]
		assert.Equal(t, "ban", last.Action)
		assert.Equal(t, []string{"waf:949110 | basic_auth: invalid credentials", "waf:949110 | basic_auth: invalid credentials"},
			last.Reasons, "the ban log must show every reason that led to it")
	})

	t.Run("weight is not partially accounted", func(t *testing.T) {
		mockFW := &MockIFirewall{}
		mockLogger := &MockILogger{}
		forgivable := ForgivableError{Duration: time.Minute, Count: 3, BanInMinute: 5}
		fw := New([]string{}, mockFW, mockLogger, nil, forgivable)

		// Spend 2 of 3 points.
		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "waf:949110 | basic_auth: invalid credentials", 2)
		mockLogger.Wg.Wait()
		assert.Empty(t, mockFW.BannedIPs)

		// The full weight no longer fits in the remaining point, so the event bans
		// instead of being discounted to a single point.
		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "waf:949110 | basic_auth: invalid credentials", 2)
		mockLogger.Wg.Wait()

		assert.Equal(t, []string{ip}, mockFW.BannedIPs)
	})

	t.Run("weight below one is treated as a single point", func(t *testing.T) {
		mockFW := &MockIFirewall{}
		mockLogger := &MockILogger{}
		forgivable := ForgivableError{Duration: time.Minute, Count: 1, BanInMinute: 5}
		fw := New([]string{}, mockFW, mockLogger, nil, forgivable)

		mockLogger.Wg.Add(2)
		fw.LogIPError(ip, "zero weight", 0)
		fw.LogIPError(ip, "negative weight", -5)
		mockLogger.Wg.Wait()

		assert.Equal(t, []string{ip}, mockFW.BannedIPs,
			"a violation must never be free unless it is explicitly observed-only")
	})

	// A report heavier than the whole budget is capped at the budget, so a single
	// (possibly forged) /logerr call can never ban an IP by itself: banning always
	// requires at least two reports within the window.
	t.Run("oversize weight is capped at the budget", func(t *testing.T) {
		mockFW := &MockIFirewall{}
		mockLogger := &MockILogger{}
		forgivable := ForgivableError{Duration: time.Minute, Count: 2, BanInMinute: 5}
		fw := New([]string{}, mockFW, mockLogger, nil, forgivable)

		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "huge weight", 100)
		mockLogger.Wg.Wait()

		assert.Equal(t, "count error", mockLogger.Logs[0].Action)
		assert.Empty(t, mockFW.BannedIPs, "one report must not ban, however heavy it claims to be")

		mockLogger.Wg.Add(1)
		fw.LogIPError(ip, "second report", DefaultWeight)
		mockLogger.Wg.Wait()

		assert.Equal(t, []string{ip}, mockFW.BannedIPs)
	})
}
