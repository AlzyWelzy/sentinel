package plugins

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/AlzyWelzy/pulsegrid-beyond/proto"
)

// MySQL / MariaDB status counters and gauges worth charting. Counters end in
// _total so the dashboard rates them.
var mysqlStatus = map[string]string{
	"Threads_connected":                "sentinel_mysql_connections",
	"Threads_running":                  "sentinel_mysql_threads_running",
	"Max_used_connections":             "sentinel_mysql_max_used_connections",
	"Questions":                        "sentinel_mysql_queries_total",
	"Slow_queries":                     "sentinel_mysql_slow_queries_total",
	"Aborted_connects":                 "sentinel_mysql_aborted_connects_total",
	"Bytes_received":                   "sentinel_mysql_received_bytes_total",
	"Bytes_sent":                       "sentinel_mysql_sent_bytes_total",
	"Innodb_buffer_pool_reads":         "sentinel_mysql_innodb_disk_reads_total",
	"Innodb_buffer_pool_read_requests": "sentinel_mysql_innodb_read_requests_total",
	"Innodb_row_lock_waits":            "sentinel_mysql_innodb_row_lock_waits_total",
	"Uptime":                           "sentinel_mysql_uptime_seconds",
}

// collectMySQL: dsn = user:pass@tcp(host:3306)/ (go-sql-driver format).
func collectMySQL(ctx context.Context, c Config) ([]proto.Sample, error) {
	dsn := setting(c, "dsn", "")
	if dsn == "" {
		return nil, fmt.Errorf("dsn is required, e.g. monitor:secret@tcp(127.0.0.1:3306)/")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, "SHOW GLOBAL STATUS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []proto.Sample
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		if metric, ok := mysqlStatus[name]; ok {
			if v, err := strconv.ParseFloat(value, 64); err == nil {
				out = append(out, sample(metric, v))
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var maxConn float64
	if err := db.QueryRowContext(ctx, "SELECT @@max_connections").Scan(&maxConn); err == nil {
		out = append(out, sample("sentinel_mysql_max_connections", maxConn))
	}
	// Replication lag, when this is a replica. Both statement names exist
	// across MySQL 8.0/8.4 and MariaDB; ignore errors (not a replica, or no
	// REPLICATION CLIENT privilege).
	for _, q := range []string{"SHOW REPLICA STATUS", "SHOW SLAVE STATUS"} {
		if lag, ok := replicaLag(ctx, db, q); ok {
			out = append(out, sample("sentinel_mysql_replication_lag_seconds", lag))
			break
		}
	}
	return out, nil
}

func replicaLag(ctx context.Context, db *sql.DB, q string) (float64, bool) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return 0, false
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil || !rows.Next() {
		return 0, false
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if rows.Scan(ptrs...) != nil {
		return 0, false
	}
	for i, col := range cols {
		if col == "Seconds_Behind_Source" || col == "Seconds_Behind_Master" {
			if v, err := strconv.ParseFloat(vals[i].String, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// collectPostgres: dsn = postgres://monitor:secret@127.0.0.1:5432/postgres
// The role needs pg_monitor for other sessions' activity.
func collectPostgres(ctx context.Context, c Config) ([]proto.Sample, error) {
	dsn := setting(c, "dsn", "")
	if dsn == "" {
		return nil, fmt.Errorf("dsn is required, e.g. postgres://monitor:secret@127.0.0.1:5432/postgres")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)

	var out []proto.Sample
	var active, idle, idleTx, total, maxConn float64
	err = conn.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'active'),
		       count(*) FILTER (WHERE state = 'idle'),
		       count(*) FILTER (WHERE state LIKE 'idle in transaction%'),
		       count(*),
		       current_setting('max_connections')::float
		  FROM pg_stat_activity WHERE backend_type = 'client backend'`).
		Scan(&active, &idle, &idleTx, &total, &maxConn)
	if err != nil {
		return nil, err
	}
	out = append(out,
		sample("sentinel_postgres_connections", active, "state", "active"),
		sample("sentinel_postgres_connections", idle, "state", "idle"),
		sample("sentinel_postgres_connections", idleTx, "state", "idle_in_transaction"),
		sample("sentinel_postgres_connections_total", total),
		sample("sentinel_postgres_max_connections", maxConn),
	)

	rows, err := conn.Query(ctx, `
		SELECT datname, xact_commit, xact_rollback, blks_read, blks_hit, deadlocks,
		       tup_inserted + tup_updated + tup_deleted, pg_database_size(datname)
		  FROM pg_stat_database
		 WHERE datname IS NOT NULL AND datname NOT IN ('template0', 'template1')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		var commits, rollbacks, reads, hits, deadlocks, writes, size float64
		if err := rows.Scan(&name, &commits, &rollbacks, &reads, &hits, &deadlocks, &writes, &size); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out,
			sample("sentinel_postgres_commits_total", commits, "database", name),
			sample("sentinel_postgres_rollbacks_total", rollbacks, "database", name),
			sample("sentinel_postgres_blocks_read_total", reads, "database", name),
			sample("sentinel_postgres_blocks_hit_total", hits, "database", name),
			sample("sentinel_postgres_deadlocks_total", deadlocks, "database", name),
			sample("sentinel_postgres_rows_written_total", writes, "database", name),
			sample("sentinel_postgres_database_size_bytes", size, "database", name),
		)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Replication: lag on a replica, and the longest-running transaction.
	var lag *float64
	if err := conn.QueryRow(ctx, `
		SELECT CASE WHEN pg_is_in_recovery()
		            THEN extract(epoch FROM now() - pg_last_xact_replay_timestamp()) END`).Scan(&lag); err == nil && lag != nil {
		out = append(out, sample("sentinel_postgres_replication_lag_seconds", *lag))
	}
	var longest *float64
	if err := conn.QueryRow(ctx, `
		SELECT extract(epoch FROM max(now() - xact_start))
		  FROM pg_stat_activity WHERE state <> 'idle' AND xact_start IS NOT NULL
		   AND backend_type = 'client backend'`).Scan(&longest); err == nil && longest != nil {
		out = append(out, sample("sentinel_postgres_longest_transaction_seconds", *longest))
	}
	return out, nil
}
