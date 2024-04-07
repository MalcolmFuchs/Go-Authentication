package storage

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHasActiveSession(t *testing.T) {

	sessionStorage := SessionStorage{
		sessions: make(map[string]session),
	}

	sessionStorage.sessions["validToken"] = session{
		expiry: time.Now().Add(1 * time.Hour),
	}

	sessionStorage.sessions["expiredToken"] = session{
		expiry: time.Now().Add(-1 * time.Hour),
	}

	sessionStorage.sessions["nonexistentToken"] = session{}

	if !sessionStorage.HasActiveSession("validToken") {
		t.Error("HasActiveSession sollte true zurückgeben für eine Sitzung mit Ablauf in der Zukunft.")
	}

	if sessionStorage.HasActiveSession("expiredToken") {
		t.Error("HasActiveSession sollte false zurückgeben für eine abgelaufene Sitzung.")
	}

	if sessionStorage.HasActiveSession("nonexistentToken") {
		t.Error("HasActiveSession sollte false zurückgeben für eine nicht vorhandene Sitzung.")
	}
}

func TestDeleteSession(t *testing.T) {
	sessionStorage := SessionStorage{
		sessions: map[string]session{
			"validToken": {
				id:     "user123",
				expiry: time.Now().Add(1 * time.Hour),
			},
		},
	}

	_, err := http.NewRequest("GET", "/delete-session", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	// Simuliere das Löschen der Sitzung
	sessionStorage.DeleteSession(rr, "validToken")

	// Überprüfe, ob die Sitzung aus der sessions-Map gelöscht wurde
	if _, exists := sessionStorage.sessions["validToken"]; exists {
		t.Errorf("Sitzung wurde nicht aus der sessions-Map gelöscht.")
	}

	// Überprüfe, ob der Cookie korrekt gesetzt wurde
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Errorf("Erwartete 1 Cookie, aber %d gefunden.", len(cookies))
	}

	deletedCookie := cookies[0]
	if deletedCookie.Name != "session_token" {
		t.Errorf("Falscher Cookie-Name. Erwartet: session_token, erhalten: %s", deletedCookie.Name)
	}

	if deletedCookie.Value != "" {
		t.Errorf("Falscher Cookie-Wert. Erwartet: leer, erhalten: %s", deletedCookie.Value)
	}

	if !deletedCookie.Expires.Before(time.Now()) {
		t.Errorf("Falsches Ablaufdatum für den Cookie. Erwartet: vor der aktuellen Zeit, erhalten: %s", deletedCookie.Expires)
	}

	if deletedCookie.MaxAge != 0 {
		t.Errorf("Falsche MaxAge für den Cookie. Erwartet: 0, erhalten: %d", deletedCookie.MaxAge)
	}

	if !deletedCookie.HttpOnly {
		t.Error("HttpOnly sollte für den Cookie gesetzt sein.")
	}

	if deletedCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Falscher SameSite für den Cookie. Erwartet: Strict, erhalten: %v", deletedCookie.SameSite)
	}

	// Überprüfe, ob die Antwort die erwartete Nachricht enthält
	expectedMessage := "Session deleted successfully!"
	if rr.Body.String() != expectedMessage {
		t.Errorf("Falsche Antwortnachricht. Erwartet: %s, erhalten: %s", expectedMessage, rr.Body.String())
	}
}

func TestRefreshSession(t *testing.T) {
	sessionStorage := SessionStorage{
		sessions: map[string]session{
			"validToken": {
				id:     "user123",
				expiry: time.Now().Add(1 * time.Hour),
			},
		},
	}

	_, err := http.NewRequest("GET", "/refresh-session", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	cookie := sessionStorage.RefreshSession(rr, "validToken")

	if cookie.Name != "session_token" {
		t.Errorf("Falscher Cookie-Name. Erwartet: session_token, erhalten: %s", cookie.Name)
	}

	if cookie.Value == "" {
		t.Error("Cookie-Wert sollte nicht leer sein.")
	}

	if !cookie.Expires.After(time.Now()) {
		t.Errorf("Falsches Ablaufdatum für den Cookie. Erwartet: in der Zukunft, erhalten: %s", cookie.Expires)
	}

	if !cookie.HttpOnly {
		t.Error("HttpOnly sollte für den Cookie gesetzt sein.")
	}

	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Falscher SameSite für den Cookie. Erwartet: Strict, erhalten: %v", cookie.SameSite)
	}
}
