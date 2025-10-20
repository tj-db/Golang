// Designed and written by Thomas de Beer.
// Do not use, copy or reproduce without his explicit written consent.
// Contact: tjdebeer@gmail.com

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"

	_ "github.com/lib/pq"
)

var routes atomic.Value
var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := loadRoutes(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", dynamicHandler)

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadRoutes() error {
	rows, err := db.Query("SELECT path, function_name FROM routes")
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
		m[path] = fn
	}

	routes.Store(m)
	log.Printf("Loaded %d routes\n", len(m))
	return nil
}

func dynamicHandler(w http.ResponseWriter, r *http.Request) {
	routeMap := routes.Load().(map[string]string)
	fnName, ok := routeMap[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	var result string
	err := db.QueryRow(fmt.Sprintf("SELECT %s();", fnName)).Scan(&result)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error executing function: %v", err), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, result)
}
