// Designed and written by Thomas de Beer.
// Do not use, copy or reproduce without his explicit written consent.
// Contact: tjdebeer@gmail.com

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	
	_ "github.com/lib/pq"
)

var routes atomic.Value
var db *sql.DB

const (
	serverAddress  = "serverAddress = "127.0.0.1:8080""
	reloadInterval = 5 * time.Second
)

var identifierPattern = regexp.MustCompile(
	`^[a-zA-Z_][a-zA-Z0-9_]*$`,
)

func main() {
	connStr := os.Getenv("DATABASE_URL")
	
	if connStr == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}
	
	var err error
	
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Database configuration error: ", err)
	}
	defer db.Close()
	
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	ctx, cancel := context.WithTimeout(
		context.Background(),
					   5*time.Second,
	)
	
	if err := db.PingContext(ctx); err != nil {
		cancel()
		log.Fatal("PostgreSQL connection failed: ", err)
	}
	
	cancel()
	
	log.Println("Connected to PostgreSQL successfully")
	
	if err := loadRoutes(); err != nil {
		log.Fatal("Route loading failed: ", err)
	}
	
	reloadCtx, stopReload := context.WithCancel(
		context.Background(),
	)
	defer stopReload()
	
	go routeReloader(reloadCtx)
	
	mux := http.NewServeMux()
	mux.HandleFunc("/", dynamicHandler)
	
	server := &http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	
	serverErrors := make(chan error, 1)
	
	go func() {
		log.Println("Server running on", serverAddress)
		serverErrors <- server.ListenAndServe()
	}()
	
	stop := make(chan os.Signal, 1)
	
	signal.Notify(
		stop,
	       syscall.SIGINT,
	       syscall.SIGTERM,
	)
	defer signal.Stop(stop)
	
	select {
		case sig := <-stop:
			log.Println("Shutdown signal received:", sig)
			
		case err := <-serverErrors:
			if err != nil && err != http.ErrServerClosed {
				log.Println("HTTP server error:", err)
			}
	}
	
	stopReload()
	
	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
							   10*time.Second,
	)
	defer shutdownCancel()
	
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Println("HTTP shutdown error:", err)
	}
	
	log.Println("Server stopped")
}

func loadRoutes() error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
					   5*time.Second,
	)
	defer cancel()
	
	rows, err := db.QueryContext(
		ctx,
		"SELECT path, function_name FROM routes",
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	
	m := make(map[string]string)
	
	for rows.Next() {
		var path, fn string
		
		if err := rows.Scan(&path, &fn); err != nil {
			return err
		}
		
		if !strings.HasPrefix(path, "/") ||
			strings.ContainsAny(path, "?#") {
				return fmt.Errorf("invalid route path: %s", path)
			}
			
			if !identifierPattern.MatchString(fn) {
				return fmt.Errorf("invalid function name: %s", fn)
			}
			
			m[path] = fn
	}
	
	if err := rows.Err(); err != nil {
		return err
	}
	
	oldRoutes := routes.Load()
	
	if oldRoutes != nil {
		oldMap := oldRoutes.(map[string]string)
		
		if mapsEqual(oldMap, m) {
			return nil
		}
	}
	
	routes.Store(m)
	
	log.Printf("Routes updated: %d routes loaded", len(m))
	
	return nil
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	
	return true
}

func routeReloader(ctx context.Context) {
	ticker := time.NewTicker(reloadInterval)
	defer ticker.Stop()
	
	for {
		select {
			case <-ctx.Done():
				return
				
			case <-ticker.C:
				if err := loadRoutes(); err != nil {
					log.Println("Route reload failed:", err)
				}
		}
	}
}

func quoteIdentifier(name string) (string, error) {
	if !identifierPattern.MatchString(name) {
		return "", fmt.Errorf("invalid SQL identifier")
	}
	
	return `"` + name + `"`, nil
}

func dynamicHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		
		http.Error(
			w,
	     "Method not allowed",
	     http.StatusMethodNotAllowed,
		)
		
		return
	}
	
	value := routes.Load()
	
	if value == nil {
		http.Error(
			w,
	     "Routes unavailable",
	     http.StatusServiceUnavailable,
		)
		return
	}
	
	routeMap := value.(map[string]string)
	
	fnName, ok := routeMap[r.URL.Path]
	
	if !ok {
		http.NotFound(w, r)
		return
	}
	
	quotedName, err := quoteIdentifier(fnName)
	
	if err != nil {
		log.Println("Invalid function name:", err)
		
		http.Error(
			w,
	     "Invalid route configuration",
	     http.StatusInternalServerError,
		)
		
		return
	}
	
	ctx, cancel := context.WithTimeout(
		r.Context(),
					   10*time.Second,
	)
	defer cancel()
	
	var result sql.NullString
	
	query := "SELECT " + quotedName + "()::text"
	
	err = db.QueryRowContext(ctx, query).Scan(&result)
	
	if err != nil {
		log.Println("Function execution failed:", err)
		
		http.Error(
			w,
	     "Internal server error",
	     http.StatusInternalServerError,
		)
		
		return
	}
	
	w.Header().Set(
		"Content-Type",
		"text/plain; charset=utf-8",
	)
	
	if result.Valid {
		fmt.Fprintln(w, result.String)
	} else {
		fmt.Fprintln(w)
	}
}
