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

	if pw, _ := users[username]; password == pw {
		cookie := CookieJar.CreateSession(username, pw)

		http.SetCookie(w, &cookie)

		w.Write([]byte("Logged In successfully"))

		return
	}

	http.Error(w, "Wrong username or password", http.StatusUnauthorized)
}

func (sessionStorage *SessionStorage) HasActiveSession(token string) bool {
	expiry := sessionStorage.sessions[token].expiry
	if time.Now().After(expiry) {
		return false
	}
	return true
}

func (sessionStorage *SessionStorage) RefreshSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "No cookie set", http.StatusUnauthorized)
			return
		}
		http.Error(w, "No cookie found", http.StatusBadRequest)
		return
	}

	sessionToken := c.Value
	userSession, ok := sessions[sessionToken]
	if !ok {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	if userSession.isExpired() {
		delete(sessions, sessionToken)
		http.Error(w, "User session expired", http.StatusUnauthorized)
		return
	}

	newSessionToken := sessionsStorage.generateToken()
	expiresAt := time.Now().Add(120 * time.Second)

	sessions[newSessionToken] = session{
		id:     userSession.id,
		expiry: expiresAt,
	}

	delete(sessions, sessionToken)

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   newSessionToken,
		Expires: time.Now().Add(120 * time.Second),
	})
}

func (sessionStorage *SessionStorage) DeleteSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, "no Cookie found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	sessionToken := c.Value

	delete(sessions, sessionToken)

	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Now(),
	})

	w.Write([]byte("Logged Out successfully"))
}
