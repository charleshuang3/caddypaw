package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/authn/gormw"
	"github.com/charleshuang3/caddypaw/pkg/authn/models"
)

func setupTestRouter(t *testing.T, webUIDir string) (*gin.Engine, *gormw.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := gormw.Open(&gormw.Config{DSN: ":memory:"})
	require.NoError(t, err)
	require.NoError(t, db.Migrate())

	router := gin.New()
	router.GET("/ban", func(c *gin.Context) { c.String(http.StatusOK, "ban-ok") })
	router.GET("/logerr", func(c *gin.Context) { c.String(http.StatusOK, "logerr-ok") })

	h := New(db, webUIDir)
	h.RegisterHandlers(router.Group("/"))
	h.RegisterStatic(router)

	return router, db
}

func TestDashboardAPIEndpoints(t *testing.T) {
	router, db := setupTestRouter(t, "")
	base := time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC)

	require.NoError(t, db.Create(&models.SecurityEvent{
		CreatedAt: base,
		Host:      "app.example.com",
		IP:        "203.0.113.5",
		Method:    "GET",
		Path:      "/admin",
		Reason:    "waf:949110",
		Weight:    1,
		Action:    "count error",
	}).Error)
	require.NoError(t, db.Create(&models.SecurityEvent{
		CreatedAt: base.Add(time.Minute),
		Host:      "app.example.com",
		IP:        "203.0.113.5",
		Method:    "POST",
		Path:      "/login",
		Reason:    "basic_auth: invalid credentials",
		Weight:    1,
		Action:    "ban",
	}).Error)

	// GET /api/events
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/events?host=app.example.com&page=1&page_size=10", nil)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var eventsResp struct {
		Items    []models.SecurityEvent `json:"items"`
		Total    int64                  `json:"total"`
		Page     int                    `json:"page"`
		PageSize int                    `json:"page_size"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &eventsResp))
	assert.Equal(t, int64(2), eventsResp.Total)
	require.Len(t, eventsResp.Items, 2)
	assert.Equal(t, "ban", eventsResp.Items[0].Action)

	// GET /api/hosts
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/hosts", nil)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "app.example.com")

	// GET /api/summary
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/summary", nil)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var summaryResp struct {
		Total    int64 `json:"total"`
		Counted  int64 `json:"counted"`
		Ban      int64 `json:"ban"`
		Observed int64 `json:"observed"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &summaryResp))
	assert.Equal(t, int64(2), summaryResp.Total)
	assert.Equal(t, int64(1), summaryResp.Counted)
	assert.Equal(t, int64(1), summaryResp.Ban)
	assert.Equal(t, int64(0), summaryResp.Observed)
}

func TestDashboardAPIValidation(t *testing.T) {
	router, _ := setupTestRouter(t, "")

	badRequests := []string{
		"/api/events?from=not-a-time",
		"/api/events?to=2026-99-99",
		"/api/events?from=2026-11-10T12:00:00Z&to=2026-11-10T10:00:00Z",
		"/api/events?page=0",
		"/api/events?page=abc",
		"/api/events?page_size=201",
		"/api/events?page_size=0",
		"/api/events?observed=maybe",
		"/api/hosts?from=bad",
		"/api/summary?to=bad",
	}

	for _, target := range badRequests {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, target, nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400 for %s", target)
	}
}

func TestDashboardStaticWebUIAndPathTraversal(t *testing.T) {
	parentDir := t.TempDir()
	webDir := filepath.Join(parentDir, "webui")
	require.NoError(t, os.MkdirAll(filepath.Join(webDir, "assets"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html>spa-index</html>"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(webDir, "assets", "app.js"), []byte("console.log('ok');"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(parentDir, "secret.txt"), []byte("top-secret"), 0o644))

	// Create a symlink inside webDir pointing outside webDir.
	_ = os.Symlink(filepath.Join(parentDir, "secret.txt"), filepath.Join(webDir, "leak.txt"))

	router, _ := setupTestRouter(t, webDir)

	// Root serves index.html.
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "spa-index")

	// Static asset serves file.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "console.log")

	// SPA route falls back to index.html.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/events/123", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "spa-index")

	// /api/* unknown route must NOT fall back to SPA.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/unknown", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Existing firewall routes still work.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/logerr", nil))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "logerr-ok", w.Body.String())

	// Path traversal attempts must never read secret.txt.
	for _, p := range []string{"/../secret.txt", "/%2e%2e/secret.txt", "/leak.txt"} {
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		assert.NotContains(t, w.Body.String(), "top-secret", "path traversal succeeded for %s", p)
	}

	// Non-GET/HEAD requests on static routes return 404 JSON.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Missing webui_dir disables static serving cleanly.
	noUIRouter, _ := setupTestRouter(t, filepath.Join(parentDir, "does-not-exist"))
	w = httptest.NewRecorder()
	noUIRouter.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
