package zerolog

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	zlog "github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/charleshuang3/caddypaw/pkg/firewall"
)

func TestZeroLog_LogEvent(t *testing.T) {
	var buf bytes.Buffer
	l := New(zlog.New(&buf), zlog.InfoLevel, "authn")

	l.LogEvent(firewall.Event{
		IP:        "192.0.2.1",
		Action:    "count error",
		Reasons:   []string{"waf:949110"},
		JailUntil: time.Time{},
		Meta: firewall.RequestMeta{
			Host:   "app.example.com",
			Method: "POST",
			Path:   "/login",
		},
	})

	var got map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "192.0.2.1", got["ip"])
	assert.Equal(t, "count error", got["action"])
	assert.Equal(t, "app.example.com", got["host"])
	assert.Equal(t, "POST", got["method"])
	assert.Equal(t, "/login", got["path"])

	buf.Reset()
	l.Log("192.0.2.2", time.Time{}, []string{"test"}, "ban", nil)
	got = map[string]any{}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.NotContains(t, got, "host")
	assert.NotContains(t, got, "method")
	assert.NotContains(t, got, "path")
}
