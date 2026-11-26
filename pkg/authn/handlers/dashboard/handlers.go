package dashboard

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/storage"
)

var logger = log.With().Str("component", "dashboard").Logger()

// Handler serves the dashboard REST API and optional static WebUI assets.
type Handler struct {
	db        *gormw.DB
	webUIRoot string
	hasWebUI  bool
}

// New creates a dashboard Handler. If webUIDir is non-empty and points to an
// existing directory, static WebUI serving with SPA fallback is enabled.
func New(db *gormw.DB, webUIDir string) *Handler {
	h := &Handler{db: db}
	if webUIDir != "" {
		if resolved, ok := resolveWebUIDir(webUIDir); ok {
			h.webUIRoot = resolved
			h.hasWebUI = true
		} else {
			logger.Warn().Str("webui_dir", webUIDir).Msg("Dashboard WebUI directory not found or not a directory; static serving disabled")
		}
	}
	return h
}

func resolveWebUIDir(dir string) (string, bool) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return resolved, true
}

// RegisterHandlers registers the dashboard REST API endpoints on rg.
func (h *Handler) RegisterHandlers(rg *gin.RouterGroup) {
	rg.GET("/api/events", h.listEvents)
	rg.GET("/api/hosts", h.listHosts)
	rg.GET("/api/summary", h.getSummary)
}

// RegisterStatic registers the static WebUI handler with SPA fallback on
// engine.NoRoute when a valid WebUIDir was configured.
func (h *Handler) RegisterStatic(engine *gin.Engine) {
	if !h.hasWebUI {
		return
	}
	engine.NoRoute(h.serveStaticOrSPA)
}

func parseTimeRange(c *gin.Context) (*time.Time, *time.Time, bool) {
	var fromPtr, toPtr *time.Time

	if rawFrom := strings.TrimSpace(c.Query("from")); rawFrom != "" {
		t, err := time.Parse(time.RFC3339Nano, rawFrom)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'from' timestamp, expected RFC3339"})
			return nil, nil, false
		}
		fromPtr = &t
	}

	if rawTo := strings.TrimSpace(c.Query("to")); rawTo != "" {
		t, err := time.Parse(time.RFC3339Nano, rawTo)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'to' timestamp, expected RFC3339"})
			return nil, nil, false
		}
		toPtr = &t
	}

	if fromPtr != nil && toPtr != nil && fromPtr.After(*toPtr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "'from' must not be after 'to'"})
		return nil, nil, false
	}

	return fromPtr, toPtr, true
}

func (h *Handler) listEvents(c *gin.Context) {
	from, to, ok := parseTimeRange(c)
	if !ok {
		return
	}

	page := 1
	if rawPage := strings.TrimSpace(c.Query("page")); rawPage != "" {
		p, err := strconv.Atoi(rawPage)
		if err != nil || p < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'page', must be >= 1"})
			return
		}
		page = p
	}

	pageSize := 50
	if rawPageSize := strings.TrimSpace(c.Query("page_size")); rawPageSize != "" {
		ps, err := strconv.Atoi(rawPageSize)
		if err != nil || ps < 1 || ps > 200 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'page_size', must be between 1 and 200"})
			return
		}
		pageSize = ps
	}

	var observed *bool
	if rawObs := strings.TrimSpace(c.Query("observed")); rawObs != "" {
		val, err := strconv.ParseBool(rawObs)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid 'observed', must be boolean"})
			return
		}
		observed = &val
	}

	query := c.Query("q")
	if query == "" {
		query = c.Query("query")
	}

	filter := storage.SecurityEventFilter{
		Page:     page,
		PageSize: pageSize,
		Host:     strings.TrimSpace(c.Query("host")),
		IP:       strings.TrimSpace(c.Query("ip")),
		Action:   strings.TrimSpace(c.Query("action")),
		Observed: observed,
		Query:    query,
		From:     from,
		To:       to,
	}

	events, total, err := storage.ListSecurityEvents(h.db, filter)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to list security events")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items":     events,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (h *Handler) listHosts(c *gin.Context) {
	from, to, ok := parseTimeRange(c)
	if !ok {
		return
	}

	hosts, err := storage.ListSecurityEventHosts(h.db, from, to)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to list security event hosts")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query hosts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"hosts": hosts,
	})
}

func (h *Handler) getSummary(c *gin.Context) {
	from, to, ok := parseTimeRange(c)
	if !ok {
		return
	}

	summary, err := storage.GetSecurityEventSummary(h.db, from, to)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get security event summary")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query summary"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

func (h *Handler) serveStaticOrSPA(c *gin.Context) {
	reqPath := c.Request.URL.Path
	if reqPath == "/api" || strings.HasPrefix(reqPath, "/api/") || reqPath == "/logerr" || reqPath == "/ban" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	cleaned := path.Clean("/" + reqPath)
	relPath := strings.TrimPrefix(cleaned, "/")
	if relPath != "" {
		if target, ok := h.safeResolveFile(relPath); ok {
			serveFileContent(c, target)
			return
		}
	}

	// SPA fallback to index.html.
	if indexFile, ok := h.safeResolveFile("index.html"); ok {
		serveFileContent(c, indexFile)
		return
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
}

func (h *Handler) safeResolveFile(relPath string) (string, bool) {
	if relPath == "" || strings.ContainsRune(relPath, '\x00') {
		return "", false
	}
	candidate := filepath.Join(h.webUIRoot, filepath.FromSlash(relPath))
	if !isWithinDir(h.webUIRoot, candidate) {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", false
	}
	if !isWithinDir(h.webUIRoot, resolved) {
		return "", false
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		return "", false
	}
	return resolved, true
}

func isWithinDir(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func serveFileContent(c *gin.Context, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	defer func() {
		_ = f.Close()
	}()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	http.ServeContent(c.Writer, c.Request, info.Name(), info.ModTime(), f)
}
