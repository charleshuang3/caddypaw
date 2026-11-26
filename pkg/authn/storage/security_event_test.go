package storage

import (
	"context"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	fw "github.com/charleshuang3/caddypaw/pkg/firewall"
	"github.com/charleshuang3/caddypaw/pkg/firewall/ipgeo"
)

func openTestDB(t *testing.T) *gormw.DB {
	t.Helper()
	db, err := gormw.Open(&gormw.Config{DSN: ":memory:"})
	require.NoError(t, err)
	require.NoError(t, db.Migrate())
	return db
}

func TestSecurityEventRecorderFlushAndClose(t *testing.T) {
	db := openTestDB(t)
	rec := NewSecurityEventRecorder(db, 16)

	now := time.Now().UTC().Truncate(time.Second)
	jail := now.Add(10 * time.Minute)

	rec.Record(fw.Event{
		Time:    now,
		IP:      "203.0.113.10",
		Action:  "count error",
		Reasons: []string{"basic_auth: invalid credentials", "waf:949110"},
		Weight:  2,
		Meta: fw.RequestMeta{
			Host:   "app.example.com",
			Method: "POST",
			Path:   "/login",
		},
		Geo: &ipgeo.IPGeo{
			Country:                      "United States",
			City:                         "San Jose",
			AutonomousSystemOrganization: "ExampleISP",
		},
	})
	rec.Record(fw.Event{
		Time:      now.Add(time.Second),
		IP:        "203.0.113.10",
		Action:    "ban",
		Reasons:   []string{"waf:949110"},
		Weight:    1,
		JailUntil: jail,
		Meta: fw.RequestMeta{
			Host:   "app.example.com",
			Method: "GET",
			Path:   "/admin",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rec.Close(ctx))
	// Idempotent close and safe Record after close.
	require.NoError(t, rec.Close(ctx))
	rec.Record(fw.Event{IP: "203.0.113.99", Action: "ban"})

	events, total, err := ListSecurityEvents(db, SecurityEventFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, events, 2)

	// Ordered by created_at DESC, id DESC.
	assert.Equal(t, "ban", events[0].Action)
	require.NotNil(t, events[0].JailUntil)
	assert.Equal(t, "count error", events[1].Action)
	assert.Equal(t, "basic_auth: invalid credentials | waf:949110", events[1].Reason)
	assert.Equal(t, "United States", events[1].Country)
	assert.Equal(t, "San Jose", events[1].City)
	assert.Equal(t, "ExampleISP", events[1].ASN)
}

func TestSecurityEventRecorderDropsWhenBufferFull(t *testing.T) {
	db := openTestDB(t)
	// Use a small buffer and flood it; Record must never block.
	rec := NewSecurityEventRecorder(db, 2)
	for i := 0; i < 200; i++ {
		rec.Record(fw.Event{
			IP:     fmt.Sprintf("203.0.113.%d", i%250),
			Action: "count error",
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rec.Close(ctx))
}

func TestListSecurityEventsFilteringAndPagination(t *testing.T) {
	db := openTestDB(t)
	base := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	seed := []models.SecurityEvent{
		{CreatedAt: base, Host: "a.example.com", IP: "1.1.1.1", Method: "GET", Path: "/100%_test", Reason: "waf:949110", Weight: 1, Observed: false, Action: "count error"},
		{CreatedAt: base.Add(time.Minute), Host: "a.example.com", IP: "1.1.1.1", Method: "GET", Path: "/login", Reason: "HACKING_ERROR", Weight: 1, Observed: false, Action: "ban"},
		{CreatedAt: base.Add(2 * time.Minute), Host: "b.example.com", IP: "2.2.2.2", Method: "POST", Path: "/dav/file", Reason: "waf:942100", Weight: 0, Observed: true, Action: "observed"},
		{CreatedAt: base.Add(3 * time.Minute), Host: "", IP: "3.3.3.3", Method: "GET", Path: "/other", Reason: "manual", Weight: 1, Observed: false, Action: "ban"},
	}
	for i := range seed {
		require.NoError(t, db.Create(&seed[i]).Error)
	}

	// Pagination clamping: PageSize > 200 clamped to 200, Page 1.
	events, total, err := ListSecurityEvents(db, SecurityEventFilter{Page: 1, PageSize: 500})
	require.NoError(t, err)
	assert.Equal(t, int64(4), total)
	assert.Len(t, events, 4)

	// Page 2 with PageSize 2.
	events, total, err = ListSecurityEvents(db, SecurityEventFilter{Page: 2, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(4), total)
	require.Len(t, events, 2)
	assert.Equal(t, "a.example.com", events[0].Host)

	// Host & Action filters.
	events, total, err = ListSecurityEvents(db, SecurityEventFilter{Host: "a.example.com", Action: "ban"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
	assert.Equal(t, "/login", events[0].Path)

	// Observed filter.
	obs := true
	events, total, err = ListSecurityEvents(db, SecurityEventFilter{Observed: &obs})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
	assert.Equal(t, "b.example.com", events[0].Host)

	// Escaped LIKE query: searching "100%_" must only match the literal path, not every row.
	events, total, err = ListSecurityEvents(db, SecurityEventFilter{Query: "100%_"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
	assert.Equal(t, "/100%_test", events[0].Path)

	// Time range filter.
	from := base.Add(time.Minute)
	to := base.Add(2 * time.Minute)
	events, total, err = ListSecurityEvents(db, SecurityEventFilter{From: &from, To: &to})
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, events, 2)

	// Hosts aggregation excludes empty host.
	hosts, err := ListSecurityEventHosts(db, nil, nil)
	require.NoError(t, err)
	require.Len(t, hosts, 2)
	assert.Equal(t, HostEventCount{Host: "a.example.com", Count: 2}, hosts[0])
	assert.Equal(t, HostEventCount{Host: "b.example.com", Count: 1}, hosts[1])

	// Summary aggregation.
	summary, err := GetSecurityEventSummary(db, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(4), summary.Total)
	assert.Equal(t, int64(1), summary.Counted)
	assert.Equal(t, int64(2), summary.Ban)
	assert.Equal(t, int64(1), summary.Observed)
	require.NotEmpty(t, summary.TopHosts)
	require.NotEmpty(t, summary.TopReasons)
}

func TestCleanupSecurityEvents(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	old := now.AddDate(0, 0, -20)
	recent := now.AddDate(0, 0, -2)

	require.NoError(t, db.Create(&models.SecurityEvent{CreatedAt: old, IP: "1.1.1.1", Action: "ban"}).Error)
	require.NoError(t, db.Create(&models.SecurityEvent{CreatedAt: recent, IP: "2.2.2.2", Action: "ban"}).Error)

	deleted, err := CleanupSecurityEvents(db, 14)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	events, total, err := ListSecurityEvents(db, SecurityEventFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
	assert.Equal(t, "2.2.2.2", events[0].IP)

	// Huge retentionDays must clamp safely rather than overflowing negative and wiping the table.
	deleted, err = CleanupSecurityEvents(db, ^uint(0))
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestTimeRangeFiltersWithNonUTCOffsets(t *testing.T) {
	db := openTestDB(t)
	rec := NewSecurityEventRecorder(db, 8)

	est := time.FixedZone("EST", -5*3600)
	cet := time.FixedZone("CET", 1*3600)

	// 12:00:00 UTC == 07:00:00 EST
	evTimeEST := time.Date(2026, 11, 10, 7, 0, 0, 0, est)
	rec.Record(fw.Event{
		Time:   evTimeEST,
		IP:     "203.0.113.50",
		Action: "count error",
		Meta:   fw.RequestMeta{Host: "tz.example.com"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rec.Close(ctx))

	// Query with +01:00 bounds around 12:00:00 UTC (12:55 CET .. 13:05 CET).
	fromCET := time.Date(2026, 11, 10, 12, 55, 0, 0, cet)
	toCET := time.Date(2026, 11, 10, 13, 5, 0, 0, cet)
	events, total, err := ListSecurityEvents(db, SecurityEventFilter{From: &fromCET, To: &toCET})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	require.Len(t, events, 1)
}

func TestListSecurityEventsPageOverflow(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.Create(&models.SecurityEvent{IP: "1.1.1.1", Action: "ban"}).Error)

	events, total, err := ListSecurityEvents(db, SecurityEventFilter{Page: math.MaxInt, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Empty(t, events)
}

func TestSecurityEventRecorderConcurrentRecordAndClose(t *testing.T) {
	db := openTestDB(t)
	rec := NewSecurityEventRecorder(db, 64)

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				rec.Record(fw.Event{
					IP:     fmt.Sprintf("198.51.100.%d", (id*50+i)%250),
					Action: "count error",
				})
			}
		}(g)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rec.Close(ctx))
	wg.Wait()
}
