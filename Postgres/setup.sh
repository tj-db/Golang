#!/bin/bash
set -Eeuo pipefail

DB_USER="go-api"

read -rp "Database name [dbname]: " input_db_name
DB_NAME="${input_db_name:-dbname}"

read -rp "Domain [db.tjdb.online]: " input_domain
DOMAIN="${input_domain:-db.tjdb.online}"

read -rp "Email for the TLS certificate: " CERT_EMAIL
if [[ -z "$CERT_EMAIL" ]]; then
    echo "ERROR: Email is required."
    exit 1
fi

DB_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
ADMIN_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

CREDENTIALS_FILE="$HOME/go-api-credentials.txt"
umask 077
cat > "$CREDENTIALS_FILE" <<EOF
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
ADMIN_TOKEN=$ADMIN_TOKEN
DOMAIN=$DOMAIN
EOF
umask 022

echo ""
echo "Generated credentials (also saved to $CREDENTIALS_FILE):"
echo "  Admin token: $ADMIN_TOKEN"
echo "  DB password: $DB_PASSWORD"
echo ""
read -rp "Press Enter once you have saved the admin token... " _

echo "Updating system..."
sudo apt update
sudo apt upgrade -y

echo "Installing required packages..."
sudo apt install -y \
    postgresql \
    postgresql-contrib \
    golang-go \
    git \
    curl \
    nginx \
    certbot \
    python3-certbot-nginx

echo "Starting PostgreSQL..."
sudo systemctl enable postgresql
sudo systemctl start postgresql

echo "Creating PostgreSQL role..."
sudo -u postgres psql -v ON_ERROR_STOP=1 \
    --set=db_user="$DB_USER" \
    --set=db_password="$DB_PASSWORD" <<'SQL'
SELECT format(
    'CREATE ROLE %I LOGIN PASSWORD %L',
    :'db_user',
    :'db_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'db_user'
)
\gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN PASSWORD %L',
    :'db_user',
    :'db_password'
)
\gexec
SQL

echo "Creating database if needed..."
sudo -u postgres psql -v ON_ERROR_STOP=1 \
    --set=db_name="$DB_NAME" \
    --set=db_user="$DB_USER" <<'SQL'
SELECT format(
    'CREATE DATABASE %I OWNER %I',
    :'db_name',
    :'db_user'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'db_name'
)
\gexec
SQL

echo "Configuring routes table and project schema..."
sudo -u postgres psql \
    -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 \
    --set=db_user="$DB_USER" <<'SQL'
CREATE TABLE IF NOT EXISTS public.routes (
    path TEXT NOT NULL,
    function_name TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    schema_name TEXT NOT NULL DEFAULT 'public',
    PRIMARY KEY (path, method)
);

ALTER TABLE public.routes
ADD COLUMN IF NOT EXISTS schema_name TEXT NOT NULL DEFAULT 'public';

GRANT USAGE, CREATE ON SCHEMA public TO :"db_user";

GRANT SELECT, INSERT, UPDATE, DELETE
ON public.routes TO :"db_user";

SELECT format(
    'CREATE SCHEMA IF NOT EXISTS project_one AUTHORIZATION %I',
    :'db_user'
)
\gexec

GRANT USAGE, CREATE ON SCHEMA project_one TO :"db_user";
SQL

echo "Restoring tables, functions and routes..."
sudo -u postgres psql \
    -d "$DB_NAME" \
    -v ON_ERROR_STOP=1 \
    --set=db_user="$DB_USER" <<'SQL'
SET ROLE :"db_user";

CREATE TABLE IF NOT EXISTS project_one.saved_data (
    id bigserial PRIMARY KEY,
    data jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION public.admin_create_schema(p_input jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
BEGIN IF p_input->>'schema_name' IS NULL OR p_input->>'schema_name' = '' THEN RAISE EXCEPTION 'schema_name is required'; END IF; EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', p_input->>'schema_name'); RETURN jsonb_build_object('status', 'success', 'schema_name', p_input->>'schema_name'); END;
$function$;

CREATE OR REPLACE FUNCTION public.admin_delete_endpoint(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
WITH deleted AS (DELETE FROM routes WHERE path = p_input->>'path' AND upper(method) = upper(p_input->>'method') RETURNING path, method, function_name) SELECT COALESCE((SELECT jsonb_build_object('status', 'deleted', 'path', path, 'method', method, 'function_name', function_name) FROM deleted), jsonb_build_object('status', 'not_found'))
$function$;

CREATE OR REPLACE FUNCTION public.admin_drop_function(p_input jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_schema text := COALESCE(NULLIF(trim(p_input->>'schema_name'), ''), 'public');
    v_function text := trim(COALESCE(p_input->>'function_name', ''));
    v_args text := trim(COALESCE(p_input->>'identity_arguments', ''));
    v_oid oid;
    v_target text;
BEGIN
    IF v_function = '' THEN
        RAISE EXCEPTION 'function_name is required';
    END IF;

    IF v_schema = 'information_schema' OR left(v_schema, 3) = 'pg_' THEN
        RAISE EXCEPTION 'protected schema';
    END IF;

    IF left(lower(v_function), 6) = 'admin_' THEN
        RAISE EXCEPTION 'protected administrative function';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.routes
        WHERE COALESCE(schema_name, 'public') = v_schema
          AND function_name = v_function
    ) THEN
        RAISE EXCEPTION 'function is still referenced by a registered route';
    END IF;

    SELECT p.oid,
           format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
    INTO v_oid, v_target
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = v_schema
      AND p.proname = v_function
      AND p.prokind = 'f'
      AND pg_get_function_identity_arguments(p.oid) = v_args;

    IF v_oid IS NULL THEN
        RAISE EXCEPTION 'function signature not found';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language l ON l.oid = p.prolang
        WHERE p.oid <> v_oid
          AND n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND l.lanname IN ('sql', 'plpgsql')
          AND p.prosrc ILIKE '%' || v_function || '%'
    ) THEN
        RAISE EXCEPTION 'function name is mentioned in another function body';
    END IF;

    EXECUTE 'DROP FUNCTION ' || v_target || ' RESTRICT';

    RETURN jsonb_build_object(
        'status', 'dropped',
        'schema_name', v_schema,
        'function_name', v_function,
        'identity_arguments', v_args
    );
END;
$function$;

CREATE OR REPLACE FUNCTION public.admin_drop_schema(p_input jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
    target text := trim(COALESCE(p_input->>'schema_name', ''));
BEGIN
    IF target = '' THEN
        RAISE EXCEPTION 'schema_name is required';
    END IF;

    IF target = 'public'
       OR target = 'information_schema'
       OR left(target, 3) = 'pg_' THEN
        RAISE EXCEPTION 'protected schema';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = target) THEN
        RAISE EXCEPTION 'schema does not exist';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.routes
        WHERE COALESCE(schema_name, 'public') = target
    ) THEN
        RAISE EXCEPTION 'schema is still referenced by registered routes';
    END IF;

    EXECUTE format('DROP SCHEMA %I RESTRICT', target);

    RETURN jsonb_build_object('status', 'dropped', 'schema_name', target);
END;
$function$;

CREATE OR REPLACE FUNCTION public.admin_inspect_functions(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
SELECT COALESCE(jsonb_agg(jsonb_build_object('signature', p.oid::regprocedure::text, 'function_name', p.proname, 'definition', pg_get_functiondef(p.oid), 'route_references', COALESCE((SELECT jsonb_agg(jsonb_build_object('path', r.path, 'method', r.method)) FROM routes r WHERE r.function_name = p.proname), '[]'::jsonb), 'catalog_dependencies', COALESCE((SELECT jsonb_agg(pg_describe_object(d.classid, d.objid, d.objsubid)) FROM pg_depend d WHERE d.refclassid = 'pg_proc'::regclass AND d.refobjid = p.oid AND d.deptype <> 'i'), '[]'::jsonb)) ORDER BY p.proname, p.oid), '[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.prokind = 'f' AND (p_input->>'function_name' IS NULL OR p.proname = p_input->>'function_name')
$function$;

CREATE OR REPLACE FUNCTION public.admin_list_endpoints(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
SELECT COALESCE(jsonb_agg(jsonb_build_object('path', path, 'method', method, 'function_name', function_name) ORDER BY path, method), '[]'::jsonb) FROM routes
$function$;

CREATE OR REPLACE FUNCTION public.admin_list_functions(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
SELECT COALESCE(jsonb_agg(jsonb_build_object('schema', n.nspname, 'name', p.proname, 'identity_arguments', pg_get_function_identity_arguments(p.oid)) ORDER BY n.nspname, p.proname), '[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.prokind = 'f' AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
$function$;

CREATE OR REPLACE FUNCTION public.admin_route_function_map(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
WITH schemas AS (
    SELECT nspname::text AS schema_name
    FROM pg_namespace
    WHERE nspname <> 'information_schema'
      AND left(nspname, 3) <> 'pg_'
),
fns AS (
    SELECT
        n.nspname::text AS schema_name,
        p.proname::text AS function_name,
        pg_get_function_identity_arguments(p.oid) AS identity_arguments,
        pg_get_function_result(p.oid) AS returns,
        l.lanname::text AS language
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
    WHERE p.prokind = 'f'
      AND n.nspname <> 'information_schema'
      AND left(n.nspname, 3) <> 'pg_'
      AND NOT EXISTS (
          SELECT 1
          FROM pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e'
      )
),
rts AS (
    SELECT
        path,
        upper(method) AS method,
        COALESCE(schema_name, 'public') AS schema_name,
        function_name
    FROM public.routes
),
fn_routes AS (
    SELECT
        f.*,
        COALESCE((
            SELECT jsonb_agg(
                jsonb_build_object('method', r.method, 'path', r.path)
                ORDER BY r.path, r.method
            )
            FROM rts r
            WHERE r.schema_name = f.schema_name
              AND r.function_name = f.function_name
        ), '[]'::jsonb) AS routes
    FROM fns f
),
by_schema AS (
    SELECT
        s.schema_name,
        COALESCE(
            jsonb_agg(
                jsonb_build_object(
                    'function_name', f.function_name,
                    'identity_arguments', f.identity_arguments,
                    'language', f.language,
                    'returns', f.returns,
                    'routes', f.routes
                )
                ORDER BY f.function_name, f.identity_arguments
            ) FILTER (WHERE f.function_name IS NOT NULL),
            '[]'::jsonb
        ) AS functions
    FROM schemas s
    LEFT JOIN fn_routes f ON f.schema_name = s.schema_name
    GROUP BY s.schema_name
)
SELECT jsonb_build_object(
    'generated_at', now(),
    'totals', jsonb_build_object(
        'schemas', (SELECT count(*) FROM by_schema),
        'functions', (SELECT count(*) FROM fns),
        'routes', (SELECT count(*) FROM rts)
    ),
    'schemas', COALESCE(
        (SELECT jsonb_object_agg(schema_name, functions) FROM by_schema),
        '{}'::jsonb
    ),
    'routes_without_function', COALESCE((
        SELECT jsonb_agg(
            jsonb_build_object(
                'method', r.method,
                'path', r.path,
                'schema_name', r.schema_name,
                'function_name', r.function_name
            )
            ORDER BY r.path, r.method
        )
        FROM rts r
        WHERE NOT EXISTS (
            SELECT 1 FROM fns f
            WHERE f.schema_name = r.schema_name
              AND f.function_name = r.function_name
        )
    ), '[]'::jsonb)
)
$function$;

CREATE OR REPLACE FUNCTION public.inspect_everything(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
SELECT jsonb_build_object('extensions', (SELECT COALESCE(jsonb_agg(extname ORDER BY extname), '[]'::jsonb) FROM pg_extension WHERE extname <> 'plpgsql'), 'functions', (SELECT COALESCE(jsonb_agg(jsonb_build_object('schema', n.nspname, 'name', p.proname, 'definition', pg_get_functiondef(p.oid)) ORDER BY n.nspname, p.proname), '[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.prokind = 'f' AND n.nspname <> 'information_schema' AND left(n.nspname, 3) <> 'pg_' AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')), 'tables', (SELECT COALESCE(jsonb_agg(jsonb_build_object('schema', n.nspname, 'name', c.relname, 'columns', (SELECT jsonb_agg(jsonb_build_object('name', a.attname, 'type', format_type(a.atttypid, a.atttypmod), 'not_null', a.attnotnull, 'default', pg_get_expr(ad.adbin, ad.adrelid)) ORDER BY a.attnum) FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), 'constraints', (SELECT COALESCE(jsonb_agg(pg_get_constraintdef(k.oid) ORDER BY k.conname), '[]'::jsonb) FROM pg_constraint k WHERE k.conrelid = c.oid), 'indexes', (SELECT COALESCE(jsonb_agg(pg_get_indexdef(i.indexrelid)), '[]'::jsonb) FROM pg_index i WHERE i.indrelid = c.oid)) ORDER BY n.nspname, c.relname), '[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r', 'p') AND n.nspname <> 'information_schema' AND left(n.nspname, 3) <> 'pg_'), 'routes', (SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY r.path, r.method), '[]'::jsonb) FROM public.routes r))
$function$;

CREATE OR REPLACE FUNCTION project_one.project1_find(p_input jsonb)
 RETURNS jsonb
 LANGUAGE sql
AS $function$
SELECT jsonb_build_object(
    'count', count(*),
    'results', COALESCE(
        jsonb_agg(
            jsonb_build_object('id', t.id, 'created_at', t.created_at, 'data', t.data)
            ORDER BY t.id DESC
        ),
        '[]'::jsonb
    )
)
FROM (
    SELECT id, created_at, data
    FROM project_one.saved_data
    WHERE data @> p_input
    ORDER BY id DESC
    LIMIT 1000
) t
$function$;

CREATE OR REPLACE FUNCTION project_one.project1_save(p_input jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_id bigint;
    v_created timestamptz;
BEGIN
    CREATE TABLE IF NOT EXISTS project_one.saved_data (
        id bigserial PRIMARY KEY,
        data jsonb NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now()
    );

    INSERT INTO project_one.saved_data (data)
    VALUES (p_input)
    RETURNING id, created_at INTO v_id, v_created;

    RETURN jsonb_build_object(
        'status', 'saved',
        'id', v_id,
        'created_at', v_created
    );
END;
$function$;

CREATE OR REPLACE FUNCTION project_one.project1_wipe(p_input jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
    v_count bigint := 0;
BEGIN
    IF COALESCE(p_input->>'confirm', '') <> 'WIPE project_one' THEN
        RAISE EXCEPTION 'confirmation required';
    END IF;

    IF to_regclass('project_one.saved_data') IS NOT NULL THEN
        SELECT count(*) INTO v_count FROM project_one.saved_data;
        TRUNCATE TABLE project_one.saved_data RESTART IDENTITY;
    END IF;

    RETURN jsonb_build_object('status', 'wiped', 'deleted_rows', v_count);
END;
$function$;

INSERT INTO public.routes (path, method, schema_name, function_name) VALUES
    ('/admin/create-schema', 'POST', 'public', 'admin_create_schema'),
    ('/admin/drop-function', 'POST', 'public', 'admin_drop_function'),
    ('/admin/drop-schema', 'POST', 'public', 'admin_drop_schema'),
    ('/admin/endpoints/delete', 'POST', 'public', 'admin_delete_endpoint'),
    ('/admin/endpoints/list', 'POST', 'public', 'admin_list_endpoints'),
    ('/admin/functions/inspect', 'POST', 'public', 'admin_inspect_functions'),
    ('/admin/functions/list', 'POST', 'public', 'admin_list_functions'),
    ('/admin/inspect-all', 'POST', 'public', 'inspect_everything'),
    ('/admin/map', 'POST', 'public', 'admin_route_function_map'),
    ('/admin/project1/wipe', 'POST', 'project_one', 'project1_wipe'),
    ('/project1/find', 'POST', 'project_one', 'project1_find'),
    ('/project1/save', 'POST', 'project_one', 'project1_save')
ON CONFLICT (path, method)
DO UPDATE SET
    schema_name = EXCLUDED.schema_name,
    function_name = EXCLUDED.function_name;

RESET ROLE;
SQL

echo "Creating Go API environment file..."
sudo install -m 600 -o root -g root /dev/null /etc/my-go-api.env

sudo tee /etc/my-go-api.env > /dev/null <<EOF
DATABASE_URL=postgres://${DB_USER}:${DB_PASSWORD}@127.0.0.1:5432/${DB_NAME}?sslmode=disable
ADMIN_TOKEN=${ADMIN_TOKEN}
EOF

sudo chmod 600 /etc/my-go-api.env
sudo chown root:root /etc/my-go-api.env

mkdir -p "$HOME/golang"

echo "Writing main.go..."
cat > "$HOME/golang/main.go" <<'GOEOF'
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

type routeTarget struct {
	SchemaName   string
	FunctionName string
}

type AddEndpointRequest struct {
	Path         string `json:"path"`
	Method       string `json:"method"`
	SchemaName   string `json:"schema_name"`
	FunctionName string `json:"function_name"`
	FunctionBody string `json:"function_body"`
	Language     string `json:"language"`
}

type DeleteFunctionRequest struct {
	SchemaName        string `json:"schema_name"`
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
		`SELECT path, method, COALESCE(schema_name, 'public'), function_name
		 FROM public.routes`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	m := make(map[routeKey]routeTarget)

	for rows.Next() {
		var path, method, schemaName, functionName string

		if err := rows.Scan(&path, &method, &schemaName, &functionName); err != nil {
			return err
		}

		method = strings.ToUpper(method)

		if !pathPattern.MatchString(path) {
			return fmt.Errorf("invalid route path: %s", path)
		}

		if !validMethod(method) {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}

		if !validSchemaName(schemaName) {
			return fmt.Errorf("invalid route schema: %s", schemaName)
		}

		if !identifierPattern.MatchString(functionName) {
			return fmt.Errorf("invalid function name: %s", functionName)
		}

		key := routeKey{Path: path, Method: method}
		m[key] = routeTarget{
			SchemaName:   schemaName,
			FunctionName: functionName,
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	oldRoutes := routes.Load()

	if oldRoutes != nil {
		oldMap := oldRoutes.(map[routeKey]routeTarget)

		if mapsEqual(oldMap, m) {
			return nil
		}
	}

	routes.Store(m)

	log.Printf("Routes updated: %d routes loaded", len(m))

	return nil
}

func mapsEqual(a, b map[routeKey]routeTarget) bool {
	if len(a) != len(b) {
		return false
	}

	for key, value := range a {
		if b[key] != value {
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

func validSchemaName(name string) bool {
	if !identifierPattern.MatchString(name) {
		return false
	}

	lowerName := strings.ToLower(name)

	if lowerName == "information_schema" ||
		strings.HasPrefix(lowerName, "pg_") {
		return false
	}

	return true
}

func schemaExists(ctx context.Context, queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, schemaName string) (bool, error) {
	var exists bool

	err := queryer.QueryRowContext(
		ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
		schemaName,
	).Scan(&exists)

	return exists, err
}

func validMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func validFunctionLanguage(language string) bool {
	switch language {
	case "sql", "plpgsql":
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

	routeMap := value.(map[routeKey]routeTarget)
	key := routeKey{Path: r.URL.Path, Method: method}

	target, ok := routeMap[key]
	if !ok {
		http.NotFound(w, r)
		return
	}

	quotedSchema, err := quoteIdentifier(target.SchemaName)
	if err != nil {
		log.Println("Invalid route schema:", err)
		http.Error(w, "Invalid route configuration", http.StatusInternalServerError)
		return
	}

	quotedFunction, err := quoteIdentifier(target.FunctionName)
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

	query := "SELECT " + quotedSchema + "." + quotedFunction + "($1::jsonb)::text"

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

	req.SchemaName = strings.TrimSpace(req.SchemaName)
	req.FunctionName = strings.TrimSpace(req.FunctionName)
	req.IdentityArguments = strings.TrimSpace(req.IdentityArguments)

	if req.SchemaName == "" {
		req.SchemaName = "public"
	}

	if !validSchemaName(req.SchemaName) ||
		!identifierPattern.MatchString(req.FunctionName) {
		http.Error(w, "Invalid schema or function name", http.StatusBadRequest)
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

	if _, err := tx.ExecContext(ctx, "LOCK TABLE public.routes IN ACCESS EXCLUSIVE MODE"); err != nil {
		log.Println("Route table lock failed:", err)
		http.Error(w, "Could not safely inspect route references", http.StatusInternalServerError)
		return
	}

	var routeInUse bool

	err = tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM public.routes
			WHERE COALESCE(schema_name, 'public') = $1
			  AND function_name = $2
		)`,
		req.SchemaName,
		req.FunctionName,
	).Scan(&routeInUse)

	if err != nil {
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
		WHERE n.nspname = $1
		  AND p.proname = $2
		  AND p.prokind = 'f'
		  AND pg_get_function_identity_arguments(p.oid) = $3
	`,
		req.SchemaName,
		req.FunctionName,
		req.IdentityArguments,
	).Scan(&dropTarget)

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
		"schema_name":        req.SchemaName,
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

	req.Method = strings.ToUpper(strings.TrimSpace(req.Method))
	req.Language = strings.ToLower(strings.TrimSpace(req.Language))
	req.Path = strings.TrimSpace(req.Path)
	req.SchemaName = strings.TrimSpace(req.SchemaName)
	req.FunctionName = strings.TrimSpace(req.FunctionName)

	if req.SchemaName == "" {
		req.SchemaName = "public"
	}

	if req.Language == "" {
		req.Language = "sql"
	}

	if !validFunctionLanguage(req.Language) {
		http.Error(w, "Unsupported function language. Use sql or plpgsql", http.StatusBadRequest)
		return
	}

	if !pathPattern.MatchString(req.Path) ||
		!validMethod(req.Method) ||
		!validSchemaName(req.SchemaName) ||
		!identifierPattern.MatchString(req.FunctionName) ||
		strings.TrimSpace(req.FunctionBody) == "" ||
		len(req.FunctionBody) > maxFunctionBodySize {
		http.Error(w, "Invalid endpoint configuration", http.StatusBadRequest)
		return
	}

	quotedSchema, err := quoteIdentifier(req.SchemaName)
	if err != nil {
		http.Error(w, "Invalid schema name", http.StatusBadRequest)
		return
	}

	quotedFunction, err := quoteIdentifier(req.FunctionName)
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

	exists, err := schemaExists(ctx, tx, req.SchemaName)
	if err != nil {
		log.Println("Schema lookup failed:", err)
		http.Error(w, "Could not inspect schema", http.StatusInternalServerError)
		return
	}

	if !exists {
		http.Error(w, "Schema does not exist", http.StatusNotFound)
		return
	}

	functionSQL := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION %s.%s(p_input jsonb)
		RETURNS jsonb
		LANGUAGE %s
		AS %s
		%s
		%s
	`,
		quotedSchema,
		quotedFunction,
		req.Language,
		delimiter,
		req.FunctionBody,
		delimiter,
	)

	if _, err := tx.ExecContext(ctx, functionSQL); err != nil {
		log.Println("Function creation failed:", err)
		http.Error(w, "Function creation failed", http.StatusBadRequest)
		return
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO public.routes (path, method, schema_name, function_name)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (path, method)
		 DO UPDATE SET
			schema_name = EXCLUDED.schema_name,
			function_name = EXCLUDED.function_name`,
		req.Path,
		req.Method,
		req.SchemaName,
		req.FunctionName,
	); err != nil {
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
		"schema_name":   req.SchemaName,
		"function_name": req.FunctionName,
		"language":      req.Language,
	})
}
GOEOF

echo "Building Go API..."
cd "$HOME/golang"
[[ -f go.mod ]] || go mod init my-go-api
go mod tidy
go build -o /tmp/my-go-api .
sudo install -m 755 /tmp/my-go-api /usr/local/bin/my-go-api

echo "Creating service user and systemd unit..."
sudo useradd --system --no-create-home --shell /usr/sbin/nologin goapi 2>/dev/null || true

sudo tee /etc/systemd/system/my-go-api.service > /dev/null <<'EOF'
[Unit]
Description=Dynamic Postgres API
After=network.target postgresql.service
Requires=postgresql.service

[Service]
User=goapi
Group=goapi
EnvironmentFile=/etc/my-go-api.env
ExecStart=/usr/local/bin/my-go-api
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable my-go-api
sudo systemctl restart my-go-api

echo "Configuring nginx..."
sudo tee /etc/nginx/sites-available/my-go-api > /dev/null <<'EOF'
server {
    listen 80;
    server_name __DOMAIN__;
    client_max_body_size 1m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 15s;
    }
}
EOF

sudo sed -i "s/__DOMAIN__/${DOMAIN}/" /etc/nginx/sites-available/my-go-api
sudo ln -sf /etc/nginx/sites-available/my-go-api /etc/nginx/sites-enabled/my-go-api
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable nginx
sudo systemctl reload nginx

echo "Requesting TLS certificate..."
sudo certbot --nginx -d "$DOMAIN" -m "$CERT_EMAIL" --agree-tos --non-interactive --redirect

echo "Verifying PostgreSQL..."
sudo -u postgres psql -d "$DB_NAME" -c "\d public.routes"
sudo -u postgres psql -d "$DB_NAME" -c "SELECT schema_name, count(*) AS routes FROM public.routes GROUP BY schema_name ORDER BY schema_name"
sudo -u postgres psql -d "$DB_NAME" -c "SELECT n.nspname AS schema, count(*) AS functions, string_agg(DISTINCT pg_get_userbyid(p.proowner), ', ') AS owner FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname IN ('public', 'project_one') AND p.prokind = 'f' GROUP BY n.nspname ORDER BY n.nspname"

echo "Verifying API..."
sleep 3
systemctl is-active my-go-api
curl -sS -X POST http://127.0.0.1:8080/admin/map \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{}' | head -c 300
echo

echo ""
echo "=========================================="
echo "INITIALISATION COMPLETED SUCCESSFULLY"
echo "=========================================="
echo "Database: $DB_NAME"
echo "Role: $DB_USER"
echo "Project schema: project_one"
echo "Domain: https://$DOMAIN"
echo "Environment: /etc/my-go-api.env"
echo "Go source: $HOME/golang/main.go"
echo "Service: my-go-api"
echo "Credentials file: $CREDENTIALS_FILE"
echo "Admin token: $ADMIN_TOKEN"
