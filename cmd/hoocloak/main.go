package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/bcrypt"

	"github.com/openhoo/hoocloak/internal/config"
	"github.com/openhoo/hoocloak/internal/idp"
	buildversion "github.com/openhoo/hoocloak/internal/version"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(os.Args[1:], os.Stdin, os.Stdout, logger); err != nil {
		logger.Error("hoocloak stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: hoocloak <serve|hash|health|version>")
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return errors.New("usage: hoocloak version")
		}
		_, err := fmt.Fprintln(stdout, buildversion.Value)
		return err
	case "hash":
		if len(args) != 1 {
			return errors.New("usage: hoocloak hash")
		}
		return hashValue(stdin, stdout)
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		path := flags.String("config", "./hoocloak.yaml", "path to YAML configuration")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("usage: hoocloak serve [--config path]")
		}
		return serve(*path, logger)
	case "health":
		return health(args[1:])
	default:
		return fmt.Errorf("unknown command %q (expected serve, hash, health, or version)", args[0])
	}
}

func hashValue(input io.Reader, output io.Writer) error {
	reader := bufio.NewReader(input)
	value, err := reader.ReadString('\n')
	if err != nil {
		return errors.New("hash input must be one newline-terminated value")
	}
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	if value == "" {
		return errors.New("hash input must not be empty")
	}
	if extra, err := io.ReadAll(reader); err != nil {
		return err
	} else if len(extra) != 0 {
		return errors.New("hash accepts exactly one value")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, string(hash))
	return err
}

func serve(path string, logger *slog.Logger) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cfg, err = applyEnvironmentOverrides(cfg)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validate effective config: %w", err)
	}
	keys := make(map[string]idp.SigningKey, len(cfg.Realms))
	for _, realm := range cfg.Realms {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("generate signing key for realm %q: %w", realm.Name, err)
		}
		thumbprint, err := (&jose.JSONWebKey{Key: &key.PublicKey}).Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("derive signing key ID for realm %q: %w", realm.Name, err)
		}
		keys[realm.Name] = idp.SigningKey{Key: key, KID: base64.RawURLEncoding.EncodeToString(thumbprint)}
	}
	provider, err := idp.NewServer(cfg, keys, logger, nil)
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: provider.Handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20,
	}
	for _, realm := range cfg.Realms {
		logger.Info("hoocloak realm configured", "realm", realm.Name, "issuer", cfg.RealmIssuer(realm.Name), "kid", keys[realm.Name].KID)
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() {
		logger.Info("hoocloak listening", "address", cfg.Listen, "realms", len(cfg.Realms))
		serverError <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownContext.Done():
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		err := <-serverError
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func health(args []string) error {
	flags := flag.NewFlagSet("health", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	target := flags.String("url", "http://127.0.0.1:8080/ready", "readiness URL")
	timeout := flags.Duration("timeout", 2*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 {
		return errors.New("usage: hoocloak health [--url URL] [--timeout duration]")
	}
	parsed, err := url.Parse(*target)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errors.New("health URL must be an absolute HTTP(S) URL without credentials")
	}
	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}

func applyEnvironmentOverrides(cfg config.Config) (config.Config, error) {
	if loginMode, configured := os.LookupEnv("HOOCLOAK_LOGIN_MODE"); configured {
		if loginMode == "" || loginMode != strings.TrimSpace(loginMode) {
			return config.Config{}, errors.New("HOOCLOAK_LOGIN_MODE must be a nonempty value without surrounding whitespace")
		}
		cfg.LoginMode = loginMode
	}
	if cfg.LoginMode == "" {
		cfg.LoginMode = config.LoginModePassword
	}
	if cfg.LoginMode != config.LoginModePassword && cfg.LoginMode != config.LoginModeSelect {
		return config.Config{}, fmt.Errorf("HOOCLOAK_LOGIN_MODE must be %q or %q", config.LoginModePassword, config.LoginModeSelect)
	}

	themeDir, configured := os.LookupEnv("HOOCLOAK_UI_THEME_DIR")
	if !configured {
		return cfg, nil
	}
	if themeDir == "" || themeDir != strings.TrimSpace(themeDir) {
		return config.Config{}, errors.New("HOOCLOAK_UI_THEME_DIR must be a nonempty path without surrounding whitespace")
	}
	if !filepath.IsAbs(themeDir) {
		return config.Config{}, errors.New("HOOCLOAK_UI_THEME_DIR must be an absolute path")
	}
	cfg.UI.ThemeDir = themeDir
	return cfg, nil
}
