package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var db *sql.DB
var jwtKey []byte

type Admin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func initDB() {
	err := godotenv.Load("database.env")
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging database:", err)
	}
	fmt.Println("Database connection successful")
}

func generateJWTKey() {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Error generating JWT key:", err)
	}
	jwtKey = key
}

func addAdminHandler(w http.ResponseWriter, r *http.Request) {
	var admin Admin
	err := json.NewDecoder(r.Body).Decode(&admin)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error hashing password: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO admins (username, password, email) VALUES (?, ?, ?)", 
		admin.Username, string(hashedPassword), admin.Email)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating admin: %v", err), http.StatusInternalServerError)
		return
	}

	// Send email with login credentials
	err = sendEmail(admin.Email, admin.Username, admin.Password)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		// Continue even if email sending fails
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Admin created successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	fmt.Println("Attempting to login with username:", creds.Username)

	var storedPassword string
	err = db.QueryRow("SELECT password FROM admins WHERE username = ?", creds.Username).Scan(&storedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(72 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func sendEmail(to, username, password string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", to)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Your CourseConnect Admin Account")
	m.SetBody("text/html", fmt.Sprintf(`
		<h1>Welcome to CourseConnect!</h1>
		<p>Your admin account has been created.</p>
		<p><strong>Username:</strong> %s<br>
		<strong>Password:</strong> %s</p>
		<p>Please log in and change your password immediately.</p>
	`, username, password))

	d := gomail.NewDialer("smtp.gmail.com", 587, to, password)

	return d.DialAndSend(m)
}

func main() {
	initDB()
	generateJWTKey()

	router := mux.NewRouter()

	router.HandleFunc("/admin", addAdminHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/login", loginHandler).Methods("POST", "OPTIONS")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Add your frontend URL
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		Debug:            true, // Enable CORS debugging
	})

	handler := c.Handler(router)

	// Add logging middleware
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, loggingHandler))
}
