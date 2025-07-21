package main

import (
    "embed"
    "encoding/json"
    "flag"
    "html/template"
    "io/ioutil"
    "log"
    "net/http"
    "time"

    "allsafeaccess/core/session"
    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templatesFS embed.FS

var (
    redisAddr  string
    listenAddr string
    secure     bool
    certFile   string
    keyFile    string
)

// User struct matches users.json schema
type User struct {
    Username string `json:"username"`
    Password string `json:"password"` // bcrypt hashed
    Role     string `json:"role"`
}

// Global user map: username -> User
var users map[string]User

func main() {
    flag.StringVar(&redisAddr, "redis", "localhost:6379", "Redis server address")
    flag.StringVar(&listenAddr, "listen", "0.0.0.0:8443", "Listen address")
    flag.BoolVar(&secure, "secure", false, "Enable TLS")
    flag.StringVar(&certFile, "cert", "config/cert.pem", "TLS certificate file path")
    flag.StringVar(&keyFile, "key", "config/key.pem", "TLS key file path")
    flag.Parse()

    var err error
    users, err = loadUsers("users.json")
    if err != nil {
        log.Fatalf("Failed to load users.json: %v", err)
    }
    log.Printf("Loaded %d users from users.json", len(users))

    sm := session.NewSessionManager(redisAddr, time.Hour*24)

    r := mux.NewRouter()
    r.HandleFunc("/", indexHandler)
    r.HandleFunc("/login", loginHandler(sm)).Methods("GET", "POST")
    r.HandleFunc("/logout", logoutHandler(sm)).Methods("POST")
    r.HandleFunc("/complete", completeHandler(sm)).Methods("GET")

    srv := &http.Server{
        Addr:    listenAddr,
        Handler: r,
    }

    log.Printf("Starting server on %s, secure=%v", listenAddr, secure)
    if secure {
        if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
            log.Fatalf("TLS server failed: %v", err)
        }
    } else {
        if err := srv.ListenAndServe(); err != nil {
            log.Fatalf("Server failed: %v", err)
        }
    }
}

// loadUsers reads users.json and returns a map username->User
func loadUsers(filename string) (map[string]User, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    var userList []User
    if err := json.Unmarshal(data, &userList); err != nil {
        return nil, err
    }
    userMap := make(map[string]User)
    for _, u := range userList {
        userMap[u.Username] = u
    }
    return userMap, nil
}

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
    tmpl, err := template.ParseFS(templatesFS, "templates/"+name)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }
    if err := tmpl.Execute(w, data); err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
    }
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
    renderTemplate(w, "index.html", nil)
}

func loginHandler(sm *session.SessionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            renderTemplate(w, "login.html", nil)
            return
        }

        username := r.FormValue("username")
        password := r.FormValue("password")

        user, ok := users[username]
        if !ok {
            renderTemplate(w, "login.html", map[string]string{"Error": "Invalid username or password"})
            return
        }

        if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
            renderTemplate(w, "login.html", map[string]string{"Error": "Invalid username or password"})
            return
        }

        // Create session token in Redis and store username + role + issued_at
        token, err := sm.CreateTokenWithMetadata(user.Username, map[string]interface{}{
            "role":      user.Role,
            "issued_at": time.Now().Unix(),
        })
        if err != nil {
            log.Printf("Error creating session token: %v", err)
            http.Error(w, "Failed to create session token", http.StatusInternalServerError)
            return
        }

        // Set token in secure HttpOnly cookie (recommended)
        cookie := http.Cookie{
            Name:     "session_token",
            Value:    token,
            Path:     "/",
            HttpOnly: true,
            Secure:   secure,
            MaxAge:   int((24 * time.Hour).Seconds()),
            SameSite: http.SameSiteLaxMode,
        }
        http.SetCookie(w, &cookie)

        // Redirect to /complete page with token as query param (optional)
        http.Redirect(w, r, "/complete?token="+token, http.StatusSeeOther)
    }
}

func logoutHandler(sm *session.SessionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session_token")
        if err != nil || cookie.Value == "" {
            http.Error(w, "Missing session token", http.StatusBadRequest)
            return
        }
        if err := sm.RevokeToken(cookie.Value); err != nil {
            http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
            return
        }
        // Remove cookie
        http.SetCookie(w, &http.Cookie{
            Name:     "session_token",
            Value:    "",
            Path:     "/",
            MaxAge:   -1,
            HttpOnly: true,
            Secure:   secure,
            SameSite: http.SameSiteLaxMode,
        })
        w.Write([]byte("Logged out successfully"))
    }
}

func completeHandler(sm *session.SessionManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token := r.URL.Query().Get("token")
        if token == "" {
            // Try from cookie as fallback
            cookie, err := r.Cookie("session_token")
            if err == nil {
                token = cookie.Value
            }
        }
        if token == "" {
            http.Error(w, "Missing token", http.StatusBadRequest)
            return
        }
        username, err := sm.ValidateToken(token)
        if err != nil {
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }
        // For demo, show username and role info from Redis
        metadata, err := sm.GetTokenMetadata(token)
        if err != nil {
            http.Error(w, "Failed to get token metadata", http.StatusInternalServerError)
            return
        }
        renderTemplate(w, "complete.html", map[string]interface{}{
            "Username": username,
            "Role":     metadata["role"],
        })
    }
}
