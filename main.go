package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var (
	db    *sql.DB
	store = sessions.NewCookieStore([]byte("super-secret-key"))
)

type User struct {
	ID       int
	Username string
	Password string
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./auth.db")
	if err != nil {
		log.Fatal(err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);`
	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}

	// Insert a default user for testing
	hash, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_, err = db.Exec("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", "admin", string(hash))
	if err != nil {
		log.Println("Default user already exists or error:", err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		errorParam := r.URL.Query().Get("error")
		successParam := r.URL.Query().Get("success")
		data := struct {
			Error   string
			Success string
		}{
			Error:   errorParam,
			Success: successParam,
		}
		tmpl := template.Must(template.ParseFiles("templates/login.html"))
		tmpl.Execute(w, data)
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hash string
		err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash)
		if err != nil || !checkPasswordHash(password, hash) {
			http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
			return
		}

		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Values["username"] = username
		session.Save(r, w)

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := session.Values["username"].(string)
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	data := struct {
		Username string
		Time     string
	}{
		Username: username,
		Time:     currentTime,
	}

	tmpl := template.Must(template.ParseFiles("templates/dashboard.html"))
	tmpl.Execute(w, data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		errorParam := r.URL.Query().Get("error")
		tmpl := template.Must(template.ParseFiles("templates/registration.html"))
		tmpl.Execute(w, errorParam)
	} else if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			http.Redirect(w, r, "/register?error=empty", http.StatusSeeOther)
			return
		}

		hash, err := hashPassword(password)
		if err != nil {
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hash)
		if err != nil {
			http.Redirect(w, r, "/register?error=exists", http.StatusSeeOther)
			return
		}

		http.Redirect(w, r, "/login?success=registered", http.StatusSeeOther)
	}
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/register", registrationHandler).Methods("GET", "POST")
	r.HandleFunc("/dashboard", dashboardHandler).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
