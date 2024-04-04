package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {

	http.HandleFunc("/", CheckForToken)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}

var (
	mutex    sync.Mutex
	sessions = map[string]session{}
	users    = map[string]string{
		"Jonas":   "YummyBBC",
		"Malcolm": "JonasYouOkay?",
	}
)

type session struct {
	id     string
	expiry time.Time
}

func (s session) isExpired() bool {
	return s.expiry.Before(time.Now())
}

func genToken() string {

	token := make([]byte, 16)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)

}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	mutex.Lock()
	defer mutex.Unlock()

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Please pass the data as URL form encoded", http.StatusBadRequest)
		return
	}

	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	if pw, ok := users[username]; ok {

		sessionToken := genToken()
		expiresAt := time.Now().Add(120 * time.Second)

		if password == pw {
			sessions[sessionToken] = session{
				id:     username,
				expiry: expiresAt,
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: expiresAt,
			// Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		w.Write([]byte("Logged In successfully"))

	} else {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	mutex.Lock()
	defer mutex.Unlock()

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

func RefreshToken(w http.ResponseWriter, r *http.Request) {

	mutex.Lock()
	defer mutex.Unlock()

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

	newSessionToken := genToken()
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

func CheckForToken(w http.ResponseWriter, r *http.Request) {

	mutex.Lock()
	defer mutex.Unlock()

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
		http.Error(w, "User session expired, please login again", http.StatusUnauthorized)
		http.HandleFunc("/login", LoginHandler)
		return
	}
}
