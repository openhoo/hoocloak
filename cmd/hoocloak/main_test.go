package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openhoo/hoocloak/internal/config"
	buildversion "github.com/openhoo/hoocloak/internal/version"
)

type echoingErrorWriter struct{}

func (echoingErrorWriter) Write(value []byte) (int, error) {
	return 0, errors.New(string(value))
}

func TestVersionCommand(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run([]string{"version"}, strings.NewReader(""), &output, logger); err != nil {
		t.Fatalf("run(version) error = %v", err)
	}
	if got := strings.TrimSpace(output.String()); got != buildversion.Value {
		t.Fatalf("version output = %q, want %q", got, buildversion.Value)
	}
}

func TestHashValueDoesNotReturnPasswordDerivedErrors(t *testing.T) {
	secret := strings.Repeat("s", 73)
	err := hashValue(strings.NewReader(secret+"\n"), io.Discard)
	if err == nil || err.Error() != "hash input exceeds bcrypt maximum length" {
		t.Fatalf("hashValue() error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("hashValue() error contains password input")
	}

	err = hashValue(strings.NewReader("password\n"), echoingErrorWriter{})
	if err == nil || err.Error() != "write password hash failed" {
		t.Fatalf("hashValue() writer error = %v", err)
	}
	if strings.Contains(err.Error(), "$2") {
		t.Fatal("hashValue() error contains generated password hash")
	}
}

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
func TestApplyEnvironmentOverridesLoginMode(t *testing.T) {
	t.Setenv("HOOCLOAK_LOGIN_MODE", config.LoginModeSelect)

	got, err := applyEnvironmentOverrides(config.Config{})
	if err != nil {
		t.Fatalf("applyEnvironmentOverrides() error = %v", err)
	}
	if got.LoginMode != config.LoginModeSelect {
		t.Fatalf("login mode = %q, want %q", got.LoginMode, config.LoginModeSelect)
	}
}

func TestApplyEnvironmentOverridesDefaultsLoginMode(t *testing.T) {
	got, err := applyEnvironmentOverrides(config.Config{})
	if err != nil {
		t.Fatalf("applyEnvironmentOverrides() error = %v", err)
	}
	if got.LoginMode != config.LoginModePassword {
		t.Fatalf("login mode = %q, want %q", got.LoginMode, config.LoginModePassword)
	}
}

func TestApplyEnvironmentOverridesRejectsInvalidLoginMode(t *testing.T) {
	t.Setenv("HOOCLOAK_LOGIN_MODE", "automatic")
	_, err := applyEnvironmentOverrides(config.Config{})
	if err == nil || !strings.Contains(err.Error(), "HOOCLOAK_LOGIN_MODE") {
		t.Fatalf("applyEnvironmentOverrides() error = %v, want environment login-mode error", err)
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
