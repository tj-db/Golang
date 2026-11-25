// Designed and written by Thomas de Beer.
// Do not use, copy or reproduce without his explicit written consent.
// Contact: tjdebeer@gmail.com

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

type routeKey struct {
	Path   string
	Method string
}

type AddEndpointRequest struct {
	Path         string `json:"path"`
	Method       string `json:"method"`
	FunctionName string `json:"function_name"`
	FunctionBody string `json:"function_body"`
}

type DeleteFunctionRequest struct {
	FunctionName      string `json:"function_name"`
	IdentityArguments string `json:"identity_arguments"`
}

var routes atomic.Value
var db *sql.DB

const (
	serverAddress       = "127.0.0.1:8080"
	reloadInterval      = 5 * time.Second
	maxRequestSize      = 1024 * 1024
	maxFunctionBodySize = 64 * 1024
)

var identifierPattern = regexp.MustCompile(
	`^[a-zA-Z_][a-zA-Z0-9_]*$`,
)

var pathPattern = regexp.MustCompile(
	`^/[A-Za-z0-9_/-]+$`,
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := db.PingContext(ctx); err != nil {
		cancel()
		log.Fatal("PostgreSQL connection failed: ", err)
	}
	cancel()

	log.Println("Connected to PostgreSQL successfully")

	if err := loadRoutes(); err != nil {
		log.Fatal("Route loading failed: ", err)
	}

	reloadCtx, stopReload := context.WithCancel(context.Background())
	defer stopReload()
	go routeReloader(reloadCtx)

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/endpoints", addEndpointHandler)
	mux.HandleFunc("/admin/functions/delete", deleteFunctionHandler)
	mux.HandleFunc("/", dynamicHandler)

	server := &http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Println("Server running on", serverAddress)
		serverErrors <- server.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Println("HTTP shutdown error:", err)
	}

	log.Println("Server stopped")
}

func loadRoutes() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(
		ctx,
		"SELECT path, method, function_name FROM routes",
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	m := make(map[routeKey]string)
	for rows.Next() {
		var path, method, fn string
		if err := rows.Scan(&path, &method, &fn); err != nil {
			return err
		}

		method = strings.ToUpper(method)
		if !pathPattern.MatchString(path) {
			return fmt.Errorf("invalid route path: %s", path)
		}
		if !validMethod(method) {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
		if !identifierPattern.MatchString(fn) {
			return fmt.Errorf("invalid function name: %s", fn)
		}

		key := routeKey{Path: path, Method: method}
		m[key] = fn
	}

	if err := rows.Err(); err != nil {
		return err
	}

	oldRoutes := routes.Load()
	if oldRoutes != nil {
		oldMap := oldRoutes.(map[routeKey]string)
		if mapsEqual(oldMap, m) {
			return nil
		}
	}

	routes.Store(m)
	log.Printf("Routes updated: %d routes loaded", len(m))
	return nil
}

func mapsEqual(a, b map[routeKey]string) bool {
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

func validMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func makeDollarDelimiter(body string) (string, error) {
	for i := 0; i < 5; i++ {
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}

		delimiter := "$api_fn_" + hex.EncodeToString(randomBytes) + "$"
		if !strings.Contains(body, delimiter) {
			return delimiter, nil
		}
	}
	return "", fmt.Errorf("could not generate SQL delimiter")
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if os.Getenv("ADMIN_TOKEN") == "" {
		http.Error(w, "Admin access is not configured", http.StatusServiceUnavailable)
		return false
	}
	if !authenticateAdmin(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func authenticateAdmin(r *http.Request) bool {
	token := os.Getenv("ADMIN_TOKEN")
	if token == "" {
		log.Println("ADMIN_TOKEN is not configured")
		return false
	}

	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return false
	}

	providedToken := parts[1]
	return len(providedToken) == len(token) &&
		subtle.ConstantTimeCompare([]byte(providedToken), []byte(token)) == 1
}

func dynamicHandler(w http.ResponseWriter, r *http.Request) {
	if (r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/")) &&
		!requireAdmin(w, r) {
		return
	}

	method := strings.ToUpper(r.Method)
	if !validMethod(method) {
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	value := routes.Load()
	if value == nil {
		http.Error(w, "Routes unavailable", http.StatusServiceUnavailable)
		return
	}

	routeMap := value.(map[routeKey]string)
	key := routeKey{Path: r.URL.Path, Method: method}
	fnName, ok := routeMap[key]
	if !ok {
		http.NotFound(w, r)
		return
	}

	quotedName, err := quoteIdentifier(fnName)
	if err != nil {
		log.Println("Invalid function name:", err)
		http.Error(w, "Invalid route configuration", http.StatusInternalServerError)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	defer r.Body.Close()

	input := []byte("{}")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Could not read request body", http.StatusBadRequest)
		return
	}

	if len(body) > 0 {
		if !json.Valid(body) {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		input = body
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var result sql.NullString
	query := "SELECT " + quotedName + "($1::jsonb)::text"
	err = db.QueryRowContext(ctx, query, string(input)).Scan(&result)
	if err != nil {
		log.Println("Function execution failed:", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if result.Valid && json.Valid([]byte(result.String)) {
		_, _ = w.Write([]byte(result.String))
	} else {
		_, _ = w.Write([]byte("null"))
	}
}

func deleteFunctionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	defer r.Body.Close()

	var req DeleteFunctionRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req.FunctionName = strings.TrimSpace(req.FunctionName)
	if !identifierPattern.MatchString(req.FunctionName) {
		http.Error(w, "Invalid function name", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(req.FunctionName, "add_route") ||
		strings.HasPrefix(strings.ToLower(req.FunctionName), "admin_") {
		http.Error(w, "Protected administrative function", http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Println("Function deletion transaction start failed:", err)
		http.Error(w, "Could not begin transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "LOCK TABLE routes IN ACCESS EXCLUSIVE MODE"); err != nil {
		log.Println("Route table lock failed:", err)
		http.Error(w, "Could not safely inspect route references", http.StatusInternalServerError)
		return
	}

	var routeInUse bool
	if err := tx.QueryRowContext(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM routes WHERE function_name = $1)",
		req.FunctionName,
	).Scan(&routeInUse); err != nil {
		log.Println("Route reference check failed:", err)
		http.Error(w, "Could not check route references", http.StatusInternalServerError)
		return
	}
	if routeInUse {
		http.Error(w, "Function is still referenced by a registered route", http.StatusConflict)
		return
	}

	var dropTarget string
	err = tx.QueryRowContext(ctx, `
		SELECT format('%I.%I(%s)', n.nspname, p.proname,
			pg_get_function_identity_arguments(p.oid))
		FROM pg_proc p
		JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'
		  AND p.proname = $1
		  AND p.prokind = 'f'
		  AND pg_get_function_identity_arguments(p.oid) = $2
	`, req.FunctionName, req.IdentityArguments).Scan(&dropTarget)
	if err == sql.ErrNoRows {
		http.Error(w, "Function signature not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Println("Function lookup failed:", err)
		http.Error(w, "Could not inspect function", http.StatusInternalServerError)
		return
	}

	if _, err := tx.ExecContext(ctx, "DROP FUNCTION "+dropTarget+" RESTRICT"); err != nil {
		log.Println("Function deletion refused or failed:", err)
		http.Error(w, "Function has dependencies or could not be deleted with RESTRICT", http.StatusConflict)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Println("Function deletion commit failed:", err)
		http.Error(w, "Could not commit function deletion", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":             "deleted",
		"function_name":      req.FunctionName,
		"identity_arguments": req.IdentityArguments,
	})
}

func addEndpointHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireAdmin(w, r) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	defer r.Body.Close()

	var req AddEndpointRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	req.Method = strings.ToUpper(req.Method)
	if !pathPattern.MatchString(req.Path) ||
		!validMethod(req.Method) ||
		!identifierPattern.MatchString(req.FunctionName) ||
		strings.TrimSpace(req.FunctionBody) == "" ||
		len(req.FunctionBody) > maxFunctionBodySize {
		http.Error(w, "Invalid endpoint configuration", http.StatusBadRequest)
		return
	}

	quotedName, err := quoteIdentifier(req.FunctionName)
	if err != nil {
		http.Error(w, "Invalid function name", http.StatusBadRequest)
		return
	}

	delimiter, err := makeDollarDelimiter(req.FunctionBody)
	if err != nil {
		log.Println("SQL delimiter generation failed:", err)
		http.Error(w, "Could not prepare function", http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Println("Transaction start failed:", err)
		http.Error(w, "Could not begin transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	functionSQL := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION public.%s(p_input jsonb)
		RETURNS jsonb
		LANGUAGE sql
		AS %s
		%s
		%s
	`,
		quotedName,
		delimiter,
		req.FunctionBody,
		delimiter,
	)

	if _, err := tx.ExecContext(ctx, functionSQL); err != nil {
		log.Println("Function creation failed:", err)
		http.Error(w, "Function creation failed", http.StatusBadRequest)
		return
	}

	var result string
	err = tx.QueryRowContext(
		ctx,
		"SELECT public.add_route($1, $2, $3)",
		req.Path,
		req.Method,
		req.FunctionName,
	).Scan(&result)
	if err != nil {
		log.Println("Route registration failed:", err)
		http.Error(w, "Route registration failed", http.StatusBadRequest)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Println("Transaction commit failed:", err)
		http.Error(w, "Could not save endpoint", http.StatusInternalServerError)
		return
	}

	if err := loadRoutes(); err != nil {
		log.Println("Route reload failed:", err)
		http.Error(w, "Endpoint saved; route reload failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":        "success",
		"message":       "Endpoint created successfully",
		"path":          req.Path,
		"method":        req.Method,
		"function_name": req.FunctionName,
	})
}
