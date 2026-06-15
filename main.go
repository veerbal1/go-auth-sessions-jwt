package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"auth-lab/api"
	"database/sql"
	_ "github.com/lib/pq"
)

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is not set")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}

	log.Println("connected to Postgres successfully")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/signup", api.SignupHandler(db))
	mux.HandleFunc("POST /api/v1/login", api.LoginHandler(db, []byte(jwtSecret)))

	addr := ":" + envOrDefault("PORT", "8080")
	log.Printf("server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
