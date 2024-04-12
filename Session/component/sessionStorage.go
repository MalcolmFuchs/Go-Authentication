package component

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

var CookieJar *SessionStorage

type session struct {
	id     string
	expiry time.Time
}

type SessionStorage struct {
	mutex    sync.Mutex
	sessions map[string]session
}

func init() {
	cookieJar := SessionStorage{
		mutex:    sync.Mutex{},
		sessions: map[string]session{},
	}

	CookieJar = &cookieJar
}

func (sessionStorage *SessionStorage) generateToken() string {
	token := make([]byte, 16)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)
}

func (sessionStorage *SessionStorage) CreateSession(username string) http.Cookie {
	token := sessionStorage.generateToken()

	sessionStorage.mutex.Lock()
	defer sessionStorage.mutex.Unlock()

	expiresAt := time.Now().Add(120 * time.Second)

	sessionStorage.sessions[token] = session{
		id:     username,
		expiry: expiresAt,
	}

	cookie := http.Cookie{
		Name:    "session_token",
		Value:   token,
		Expires: expiresAt,
		// Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return cookie
}

func (sessionStorage *SessionStorage) HasActiveSession(token http.Cookie) bool {
	expiry := sessionStorage.sessions[token.Value].expiry
	return !time.Now().After(expiry)
}

func (sessionStorage *SessionStorage) DeleteSession(token *http.Cookie) http.Cookie {

	sessionStorage.mutex.Lock()
	defer sessionStorage.mutex.Unlock()

	delete(sessionStorage.sessions, token.Value)

	deletedCookie := http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
		// Secure:   true,
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return deletedCookie
}

func (sessionStorage *SessionStorage) RefreshSession(token http.Cookie) (http.Cookie, error) {
	sessionStorage.mutex.Lock()

	if !sessionStorage.HasActiveSession(token) {
		return http.Cookie{Name: "", Value: ""}, errors.New("No active session for token found")
	}

	username := sessionStorage.sessions[token.Value].id
	sessionStorage.DeleteSession(&token)

	sessionStorage.mutex.Unlock()

	cookie := sessionStorage.CreateSession(username)

	return cookie, nil
}
