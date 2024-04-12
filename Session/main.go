package main

import (
	"Authorization/component"
	"fmt"
	"net/http"
)

var users = map[string]string{
	"Jonas":   "YummyBBC",
	"Malcolm": "JonasYouOkay?",
}

func main() {

	http.HandleFunc("/", IsLoggedIn)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	fmt.Println("Server is running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
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
		cookie := component.CookieJar.CreateSession(username)

		http.SetCookie(w, &cookie)

		w.Write([]byte("Logged In successfully"))

		return
	}

	http.Error(w, "Wrong username or password", http.StatusUnauthorized)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	token, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Logout unsuccessfully", http.StatusBadRequest)
		return
	}
	deletedCookie := component.CookieJar.DeleteSession(token)

	http.SetCookie(w, &deletedCookie)

	w.Write([]byte("Session deleted successfully!"))
}

func IsLoggedIn(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "User not logged in", http.StatusUnauthorized)
		return
	}
	component.CookieJar.RefreshSession(*token)

}
