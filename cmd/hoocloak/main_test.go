package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openhoo/hoocloak/internal/config"
)

func TestApplyEnvironmentOverridesThemeDirectory(t *testing.T) {
	t.Setenv("HOOCLOAK_UI_THEME_DIR", "/opt/hoocloak/theme")
	cfg := config.Config{UI: config.UIConfig{ThemeDir: "/from/config"}}

	got, err := applyEnvironmentOverrides(cfg)
	if err != nil {
		t.Fatalf("applyEnvironmentOverrides() error = %v", err)
	}
	if got.UI.ThemeDir != "/opt/hoocloak/theme" {
		t.Fatalf("theme directory = %q", got.UI.ThemeDir)
	}
}

func TestHealthChecksStatusWithoutFollowingRedirects(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "ready", status: http.StatusOK},
		{name: "unavailable", status: http.StatusServiceUnavailable, wantErr: "503 Service Unavailable"},
		{name: "redirect", status: http.StatusFound, wantErr: "302 Found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			err := health([]string{"--url", server.URL, "--timeout", "1s"})
			if tt.wantErr == "" && err != nil {
				t.Fatalf("health() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("health() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHealthRejectsUnsafeURL(t *testing.T) {
	for _, target := range []string{"/ready", "file:///etc/passwd", "http://user:pass@localhost/ready"} {
		if err := health([]string{"--url", target}); err == nil {
			t.Fatalf("health(%q) unexpectedly succeeded", target)
		}
	}
}

func TestApplyEnvironmentOverridesRejectsRelativeThemeDirectory(t *testing.T) {
	t.Setenv("HOOCLOAK_UI_THEME_DIR", "./theme")
	_, err := applyEnvironmentOverrides(config.Config{})
	if err == nil || !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("applyEnvironmentOverrides() error = %v, want absolute-path error", err)
	}
}
