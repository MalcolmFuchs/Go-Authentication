package storage

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

var CookieJar *SessionStorage

var users = map[string]string{
	"Jonas":   "YummyBBC",
	"Malcolm": "JonasYouOkay?",
}

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

func (sessionStorage *SessionStorage) CreateSession(username, password string) http.Cookie {
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

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if pw := users[username]; password == pw {
		cookie := CookieJar.CreateSession(username, pw)

		http.SetCookie(w, &cookie)

		w.Write([]byte("Logged In successfully"))

		return
	}

	http.Error(w, "Wrong username or password", http.StatusUnauthorized)
}

func (sessionStorage *SessionStorage) HasActiveSession(token string) bool {
	expiry := sessionStorage.sessions[token].expiry
	return !time.Now().After(expiry)
}

func (sessionStorage *SessionStorage) DeleteSession(w http.ResponseWriter, token string) {

	delete(sessionStorage.sessions, token)

	deletedCookie := http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
		// Secure:   true,
		MaxAge:   0,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &deletedCookie)

	w.Write([]byte("Session deleted successfully!"))

}

func (sessionStorage *SessionStorage) RefreshSession(w http.ResponseWriter, token string) http.Cookie {

	if !sessionStorage.HasActiveSession(token) {
		http.Error(w, "No valid cookie found", http.StatusUnauthorized)
		sessionStorage.DeleteSession(w, token)
	}

	newToken := sessionStorage.generateToken()
	expiresAt := time.Now().Add(120 * time.Second)

	cookie := http.Cookie{
		Name:    "session_token",
		Value:   newToken,
		Expires: expiresAt,
		// Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return cookie
}
