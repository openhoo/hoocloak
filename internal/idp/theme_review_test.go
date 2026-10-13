package idp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoocloak/internal/config"
)

const reviewThemeForm = `<form method="post" action="{{.BasePath}}/login"><input type="hidden" name="authRequestID"><input type="hidden" name="csrf">{{if eq .Mode "select"}}<select name="identity"><option value="user-id">User</option></select>{{else}}<input name="username"><input name="password" type="password">{{end}}</form>`

func TestThemeRequiresAssetsDirectory(t *testing.T) {
	themeDir := writeExternalTheme(t, reviewThemeForm)
	if err := os.Remove(filepath.Join(themeDir, "assets")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(themeDir, "assets"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadUI(themeDir); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("loadUI() error = %v, want assets directory rejection", err)
	}
}

func TestThemeSelfClosingHTMLKeepsBrowserSemantics(t *testing.T) {
	const basePath = "/realms/theme-review"
	form := `<form method="post" action="` + basePath + `/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></form>`
	for _, wrapper := range []string{"template", "textarea"} {
		t.Run(wrapper, func(t *testing.T) {
			if err := validateLoginHTML("<"+wrapper+"/>"+form+"</"+wrapper+">", basePath, config.LoginModePassword, "request-id", "csrf-token"); err == nil {
				t.Fatal("inert required controls were accepted")
			}
		})
	}
	if err := validateLoginHTML(`<svg/><div/>`+form, basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
		t.Fatalf("valid self-closing foreign element rejected: %v", err)
	}
}

func TestThemeMandatoryControlsAreSuccessful(t *testing.T) {
	const basePath = "/realms/theme-review"
	form := `<form method="post" action="` + basePath + `/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token"><input name="username"><input name="password" type="password"></form>`
	for _, control := range []string{
		`<input name="username" type="button">`,
		`<input name="username" type="reset">`,
		`<input name="username" type="submit">`,
		`<input name="username" type="image">`,
		`<input name="username" type="file">`,
		`<input name="username" type="checkbox">`,
		`<input name="username" type="checkbox" checked>`,
		`<input name="username" type="radio">`,
		`<button name="username">Sign in</button>`,
	} {
		t.Run(control, func(t *testing.T) {
			body := strings.Replace(form, `<input name="username">`, control, 1)
			if err := validateLoginHTML(body, basePath, config.LoginModePassword, "request-id", "csrf-token"); err == nil {
				t.Fatal("non-submitting username control was accepted")
			}
		})
	}
	for _, replacement := range []struct{ from, to string }{
		{`<input type="hidden" name="authRequestID" value="request-id">`, `<textarea type="hidden" name="authRequestID" value="request-id"></textarea>`},
		{`<input type="hidden" name="csrf" value="csrf-token">`, `<select type="hidden" name="csrf" value="csrf-token"><option>Wrong</option></select>`},
		{`<input name="password" type="password">`, `<select name="password" type="password"><option>Wrong</option></select>`},
	} {
		if err := validateLoginHTML(strings.Replace(form, replacement.from, replacement.to, 1), basePath, config.LoginModePassword, "request-id", "csrf-token"); err == nil {
			t.Fatalf("non-input required control accepted: %s", replacement.to)
		}
	}
	if err := validateLoginHTML(strings.Replace(form, `<input name="username">`, `<textarea name="username">alice</textarea>`, 1), basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
		t.Fatalf("successful textarea username rejected: %v", err)
	}
	if err := validateLoginHTML(strings.Replace(form, `<input name="username">`, `<input name="username" type="hidden" value="alice">`, 1), basePath, config.LoginModePassword, "request-id", "csrf-token"); err != nil {
		t.Fatalf("successful fixed username rejected: %v", err)
	}
}

func TestThemeIdentityControlsUseEnabledScalarOptions(t *testing.T) {
	const basePath = "/realms/theme-review"
	form := `<form method="post" action="` + basePath + `/login"><input type="hidden" name="authRequestID" value="request-id"><input type="hidden" name="csrf" value="csrf-token">CONTROL</form>`
	for _, control := range []string{
		`<input name="identity" type="button">`,
		`<select name="identity"></select>`,
		`<select name="identity"><option value="">Choose a user</option></select>`,
		`<select name="identity"><option> </option></select>`,
		`<select name="identity"><option><script>"alice"</script></option></select>`,
		`<select name="identity"><option disabled value="user-id">User</option></select>`,
		`<select name="identity"><optgroup disabled><option value="user-id">User</option></optgroup></select>`,
		`<select name="identity" multiple><option selected value="user-id">User</option><option selected value="other">Other</option></select>`,
		`<select name="identity"><template shadowrootmode="open"><option value="user-id">User</option></template></select>`,
		`<select name="identity"><select name="display"><option value="user-id">User</option></select>`,
		`<select name="identity"><input name="display"><option value="user-id">User</option></select>`,
		`<select name="identity"><textarea name="display">Display</textarea><option>User</option></select>`,
	} {
		t.Run(control, func(t *testing.T) {
			if err := validateLoginHTML(strings.Replace(form, "CONTROL", control, 1), basePath, config.LoginModeSelect, "request-id", "csrf-token"); err == nil {
				t.Fatal("identity control without a scalar successful value accepted")
			}
		})
	}
	for _, control := range []string{
		`<select name="identity"><option disabled>Choose a user</option><optgroup disabled><option value="other">Other</option></optgroup><option value="user-id">User</option></select>`,
		`<select name="identity"><optgroup disabled><option value="other">Other</option></optgroup><optgroup><option value="user-id">User</option></optgroup></select>`,
		`<select name="identity"><option>User</option></select>`,
		`<select name="identity"><option>Al<script>"ignored"</script>ice</option></select>`,
		`<select name="identity"><option value="">Choose a user</option><option>User</option></select>`,
		`<input name="identity" type="radio" value="user-id" checked>`,
	} {
		if err := validateLoginHTML(strings.Replace(form, "CONTROL", control, 1), basePath, config.LoginModeSelect, "request-id", "csrf-token"); err != nil {
			t.Fatalf("successful identity control rejected: %v", err)
		}
	}
}

func TestThemePreflightChecksInitialLoginStates(t *testing.T) {
	for _, mode := range []string{config.LoginModePassword, config.LoginModeSelect} {
		t.Run(mode, func(t *testing.T) {
			login := `{{if and (eq .Mode "` + mode + `") (not .Error)}}<p>No login form</p>{{else}}` + reviewThemeForm + `{{end}}`
			if _, _, err := loadUI(writeExternalTheme(t, login)); err == nil {
				t.Fatal("theme missing the initial login form was accepted")
			}
		})
	}
}
