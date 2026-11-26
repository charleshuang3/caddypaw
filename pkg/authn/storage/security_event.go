package storage

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-co-op/gocron/v2"
	"gorm.io/gorm"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
	fw "github.com/charleshuang3/caddypaw/pkg/firewall"
)

const (
	defaultEventBufferSize = 1024
	defaultPageSize        = 50
	maxPageSize            = 200
	defaultSummaryTopLimit = 10
)

// SecurityEventRecorder asynchronously persists firewall events into the DB.
type SecurityEventRecorder struct {
	db      *gormw.DB
	ch      chan fw.Event
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	dropped atomic.Int64
}

// NewSecurityEventRecorder creates a buffered async recorder and starts its
// background writer goroutine.
func NewSecurityEventRecorder(db *gormw.DB, bufferSize int) *SecurityEventRecorder {
	if bufferSize <= 0 {
		bufferSize = defaultEventBufferSize
	}
	r := &SecurityEventRecorder{
		db:   db,
		ch:   make(chan fw.Event, bufferSize),
		done: make(chan struct{}),
	}
	go r.run()
	return r
}

// Record enqueues a firewall event without blocking. If the buffer is full or
// the recorder has been closed, the event is dropped.
func (r *SecurityEventRecorder) Record(ev fw.Event) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.closed {
		return
	}

	select {
	case r.ch <- ev:
	default:
		r.dropped.Add(1)
		logger.Warn().
			Str("ip", ev.IP).
			Str("action", ev.Action).
			Msg("Security event buffer full, dropping event")
	}
}

// Dropped returns the number of events dropped due to a full buffer.
func (r *SecurityEventRecorder) Dropped() int64 {
	return r.dropped.Load()
}

// Close stops accepting new events and waits for buffered events to be flushed
// to the database or until ctx is cancelled.
func (r *SecurityEventRecorder) Close(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.ch)
	}
	r.mu.Unlock()

	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *SecurityEventRecorder) run() {
	defer close(r.done)
	for ev := range r.ch {
		record := eventToModel(ev)
		if err := r.db.Create(record).Error; err != nil {
			logger.Warn().
				Err(err).
				Str("ip", ev.IP).
				Str("action", ev.Action).
				Msg("Failed to persist security event")
		}
	}
}

func eventToModel(ev fw.Event) *models.SecurityEvent {
	createdAt := ev.Time
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	createdAt = createdAt.UTC()

	var jailUntil *time.Time
	if !ev.JailUntil.IsZero() {
		t := ev.JailUntil.UTC()
		jailUntil = &t
	}

	var country, city, asn string
	if ev.Geo != nil {
		country = ev.Geo.Country
		city = ev.Geo.City
		asn = ev.Geo.AutonomousSystemOrganization
	}

	return &models.SecurityEvent{
		CreatedAt: createdAt,
		Host:      ev.Meta.Host,
		IP:        ev.IP,
		Method:    ev.Meta.Method,
		Path:      ev.Meta.Path,
		Reason:    strings.Join(ev.Reasons, " | "),
		Weight:    ev.Weight,
		Observed:  ev.Observed,
		Action:    ev.Action,
		JailUntil: jailUntil,
		Country:   country,
		City:      city,
		ASN:       asn,
	}
}

// SecurityEventFilter specifies pagination and filtering options for listing
// security events.
type SecurityEventFilter struct {
	Page     int
	PageSize int
	Host     string
	IP       string
	Action   string
	Observed *bool
	Query    string
	From     *time.Time
	To       *time.Time
}

// HostEventCount represents event counts grouped by host.
type HostEventCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// ReasonEventCount represents event counts grouped by reason.
type ReasonEventCount struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// SecurityEventSummary holds aggregated security event statistics.
type SecurityEventSummary struct {
	Total      int64              `json:"total"`
	Counted    int64              `json:"counted"`
	Ban        int64              `json:"ban"`
	Observed   int64              `json:"observed"`
	TopHosts   []HostEventCount   `json:"top_hosts"`
	TopReasons []ReasonEventCount `json:"top_reasons"`
}

var likeEscaper = strings.NewReplacer(
	`\`, `\\`,
	`%`, `\%`,
	`_`, `\_`,
)

func escapeLikePattern(q string) string {
	return "%" + strings.ToLower(likeEscaper.Replace(q)) + "%"
}

func applySecurityEventTimeRange(q *gorm.DB, from, to *time.Time) *gorm.DB {
	if from != nil {
		q = q.Where("created_at >= ?", from.UTC())
	}
	if to != nil {
		q = q.Where("created_at <= ?", to.UTC())
	}
	return q
}

// ListSecurityEvents returns a paginated list of security events matching the
// filter, along with the total matching count.
func ListSecurityEvents(db *gormw.DB, filter SecurityEventFilter) ([]models.SecurityEvent, int64, error) {
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = defaultPageSize
	} else if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	q := db.Model(&models.SecurityEvent{})
	q = applySecurityEventTimeRange(q, filter.From, filter.To)

	if filter.Host != "" {
		q = q.Where("host = ?", filter.Host)
	}
	if filter.IP != "" {
		q = q.Where("ip = ?", filter.IP)
	}
	if filter.Action != "" {
		q = q.Where("action = ?", filter.Action)
	}
	if filter.Observed != nil {
		q = q.Where("observed = ?", *filter.Observed)
	}
	if filter.Query != "" {
		pattern := escapeLikePattern(filter.Query)
		q = q.Where(
			`(LOWER(reason) LIKE ? ESCAPE '\' OR LOWER(path) LIKE ? ESCAPE '\' OR LOWER(ip) LIKE ? ESCAPE '\' OR LOWER(host) LIKE ? ESCAPE '\')`,
			pattern, pattern, pattern, pattern,
		)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	events := make([]models.SecurityEvent, 0)
	if page-1 > math.MaxInt/pageSize {
		return events, total, nil
	}
	offset := (page - 1) * pageSize
	if err := q.Order("created_at DESC, id DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&events).Error; err != nil {
		return nil, 0, err
	}

	return events, total, nil
}

// ListSecurityEventHosts returns distinct non-empty hosts with their event counts.
func ListSecurityEventHosts(db *gormw.DB, from, to *time.Time) ([]HostEventCount, error) {
	q := db.Model(&models.SecurityEvent{}).
		Select("host, COUNT(*) AS count").
		Where("host <> ''")
	q = applySecurityEventTimeRange(q, from, to)

	hosts := make([]HostEventCount, 0)
	if err := q.Group("host").
		Order("count DESC, host ASC").
		Scan(&hosts).Error; err != nil {
		return nil, err
	}
	return hosts, nil
}

// GetSecurityEventSummary returns total, counted/error, ban, and observed
// counts along with top hosts and top reasons.
func GetSecurityEventSummary(db *gormw.DB, from, to *time.Time) (*SecurityEventSummary, error) {
	summary := &SecurityEventSummary{
		TopHosts:   make([]HostEventCount, 0),
		TopReasons: make([]ReasonEventCount, 0),
	}

	base := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to)
	if err := base.Count(&summary.Total).Error; err != nil {
		return nil, err
	}

	countedQ := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to).
		Where("action = ?", "count error")
	if err := countedQ.Count(&summary.Counted).Error; err != nil {
		return nil, err
	}

	banQ := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to).
		Where("action = ?", "ban")
	if err := banQ.Count(&summary.Ban).Error; err != nil {
		return nil, err
	}

	observedQ := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to).
		Where("observed = ?", true)
	if err := observedQ.Count(&summary.Observed).Error; err != nil {
		return nil, err
	}

	hostsQ := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to).
		Select("host, COUNT(*) AS count").
		Where("host <> ''").
		Group("host").
		Order("count DESC, host ASC").
		Limit(defaultSummaryTopLimit)
	if err := hostsQ.Scan(&summary.TopHosts).Error; err != nil {
		return nil, err
	}

	reasonsQ := applySecurityEventTimeRange(db.Model(&models.SecurityEvent{}), from, to).
		Select("reason, COUNT(*) AS count").
		Where("reason <> ''").
		Group("reason").
		Order("count DESC, reason ASC").
		Limit(defaultSummaryTopLimit)
	if err := reasonsQ.Scan(&summary.TopReasons).Error; err != nil {
		return nil, err
	}

	return summary, nil
}

const maxRetentionDays uint = 36500

// CleanupSecurityEvents deletes security events older than retentionDays.
func CleanupSecurityEvents(db *gormw.DB, retentionDays uint) (int64, error) {
	if retentionDays == 0 {
		return 0, nil
	}
	if retentionDays > maxRetentionDays {
		retentionDays = maxRetentionDays
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -int(retentionDays))
	res := db.Where("created_at < ?", cutoff).Delete(&models.SecurityEvent{})
	return res.RowsAffected, res.Error
}

// RegisterSecurityEventsCleaner schedules a daily job to delete security events
// older than retentionDays.
func RegisterSecurityEventsCleaner(scheduler gocron.Scheduler, db *gormw.DB, retentionDays uint) {
	if retentionDays == 0 {
		return
	}
	_, _ = scheduler.NewJob(
		gocron.CronJob(
			// 4am Daily
			"0 4 * * *",
			false,
		),
		gocron.NewTask(
			func() {
				logger.Info().Uint("retention_days", retentionDays).Msg("Cleaning up expired security events")
				if _, err := CleanupSecurityEvents(db, retentionDays); err != nil {
					logger.Warn().Err(err).Msg("Failed to clean up expired security events")
				}
			},
		),
	)
}
