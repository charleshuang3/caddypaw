package statisfiles

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestStaticFileHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	testGroup := router.Group("/")
	RegisterHandlers(testGroup)

	// Test case: Request a static file
	req, err := http.NewRequest("GET", "/static/google-logo.png", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the status code
	assert.Equal(t, http.StatusOK, rr.Code, "handler returned wrong status code")

	// Check the content type
	expectedContentType := "image/png"
	assert.Equal(t, expectedContentType, rr.Header().Get("Content-Type"), "handler returned wrong content type")
}

func TestStaticFileHandler_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	testGroup := router.Group("/")
	RegisterHandlers(testGroup)

	// Test case: Request a non-existent file
	req, err := http.NewRequest("GET", "/static/nonexistent.txt", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the status code
	assert.Equal(t, http.StatusNotFound, rr.Code, "handler returned wrong status code for non-existent file")
}
