package dbinspect

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gssh "gashboard/bridge/internal/ssh"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const queryTimeout = 10 * time.Second

// TargetSpec identifies an inspectable database target (confined local SQLite or active 127.0.0.1 SSH tunnel).
type TargetSpec struct {
	TargetID   string `json:"target_id"`
	Engine     string `json:"engine"` // sqlite | postgres | mariadb
	SQLitePath string `json:"sqlite_path,omitempty"`
	TunnelID   string `json:"tunnel_id,omitempty"`
	DirectHost string `json:"host,omitempty"` // rejected if non-empty to block direct public DB admin access
	DBUser     string `json:"db_user,omitempty"`
	DBPassword string `json:"db_password,omitempty"`
	DBName     string `json:"db_name,omitempty"`
	SchemaName string `json:"schema_name,omitempty"`
}

// IndexMeta describes a table index.
type IndexMeta struct {
	Name    string   `json:"name"`
	Unique  bool     `json:"unique"`
	Columns []string `json:"columns"`
}

// ForeignKeyMeta describes a foreign-key relationship.
type ForeignKeyMeta struct {
	Column    string `json:"column"`
	RefTable  string `json:"ref_table"`
	RefColumn string `json:"ref_column"`
	OnUpdate  string `json:"on_update"`
	OnDelete  string `json:"on_delete"`
}

// TableSchema captures metadata and exact base-10 row count for one table.
type TableSchema struct {
	Name        string           `json:"name"`
	Schema      string           `json:"schema"`
	RowCount    string           `json:"row_count"`
	Columns     []ColumnMeta     `json:"columns"`
	Indexes     []IndexMeta      `json:"indexes"`
	ForeignKeys []ForeignKeyMeta `json:"foreign_keys"`
}

// SchemaResult holds full schema discovery output.
type SchemaResult struct {
	OK          bool          `json:"ok"`
	Engine      string        `json:"engine"`
	TargetLabel string        `json:"target_label"`
	Databases   []string      `json:"databases"`
	Tables      []TableSchema `json:"tables"`
}

// RowsRequest configures bounded, parameterized table browsing.
type RowsRequest struct {
	Target    TargetSpec `json:"target"`
	Table     string     `json:"table"`
	Page      string     `json:"page"`
	Limit     string     `json:"limit"`
	SortCol   string     `json:"sort_col,omitempty"`
	SortDir   string     `json:"sort_dir,omitempty"`
	FilterCol string     `json:"filter_col,omitempty"`
	FilterOp  string     `json:"filter_op,omitempty"`
	FilterVal string     `json:"filter_val,omitempty"`
}

// RowsResult returns paginated table rows with exact ADR-025c base-10 wire strings.
type RowsResult struct {
	OK         bool             `json:"ok"`
	Engine     string           `json:"engine"`
	Table      string           `json:"table"`
	Page       string           `json:"page"`
	Limit      string           `json:"limit"`
	TotalRows  string           `json:"total_rows"`
	TotalPages string           `json:"total_pages"`
	Columns    []ColumnMeta     `json:"columns"`
	Rows       []map[string]any `json:"rows"`
}

// QueryRequest executes a read-only SQL query.
type QueryRequest struct {
	Target TargetSpec `json:"target"`
	SQL    string     `json:"sql"`
}

// QueryResult captures bounded read-only query results.
type QueryResult struct {
	OK        bool             `json:"ok"`
	Engine    string           `json:"engine"`
	Verb      string           `json:"verb"`
	ReadOnly  bool             `json:"read_only"`
	Truncated bool             `json:"truncated"`
	RowCount  string           `json:"row_count"`
	Columns   []ColumnMeta     `json:"columns"`
	Rows      []map[string]any `json:"rows"`
}

// MutatePlanRequest previews a write/DDL/import operation and creates a Pre-Mutation Snapshot.
type MutatePlanRequest struct {
	Target TargetSpec `json:"target"`
	SQL    string     `json:"sql"`
}

// MutatePlanResult summarizes impact and returns captured Pre-Mutation Snapshot metadata.
type MutatePlanResult struct {
	OK             bool   `json:"ok"`
	Engine         string `json:"engine"`
	Kind           string `json:"kind"`
	Verb           string `json:"verb"`
	TableName      string `json:"table_name"`
	StatementCount string `json:"statement_count"`
	PlainSummary   string `json:"plain_summary"`
	SnapshotID     string `json:"snapshot_id"`
	SnapshotPath   string `json:"snapshot_path"`
	BackupSHA256   string `json:"backup_sha256"`
	PreRowCount    string `json:"pre_row_count"`
}

// MutateExecuteRequest executes an approved DML/DDL/import statement inside a transaction.
type MutateExecuteRequest struct {
	Target     TargetSpec `json:"target"`
	SQL        string     `json:"sql"`
	SnapshotID string     `json:"snapshot_id,omitempty"`
}

// MutateExecuteResult reports atomic mutation results.
type MutateExecuteResult struct {
	OK                 bool   `json:"ok"`
	Engine             string `json:"engine"`
	Kind               string `json:"kind"`
	Verb               string `json:"verb"`
	TableName          string `json:"table_name"`
	StatementsExecuted string `json:"statements_executed"`
	AffectedRows       string `json:"affected_rows"`
	SnapshotID         string `json:"snapshot_id"`
}

// ExportRequest exports sanitized DDL + DML SQL for one table (or all tables).
type ExportRequest struct {
	Target      TargetSpec `json:"target"`
	Table       string     `json:"table,omitempty"`
	SaveFile    bool       `json:"save_file,omitempty"`
	Filename    string     `json:"filename,omitempty"`
}

// ExportResult returns generated SQL dump and optional confined export path.
type ExportResult struct {
	OK         bool   `json:"ok"`
	Engine     string `json:"engine"`
	SQLDump    string `json:"sql_dump"`
	ExportPath string `json:"export_path,omitempty"`
	SHA256     string `json:"sha256"`
	TableCount string `json:"table_count"`
	RowCount   string `json:"row_count"`
}

// RestoreRequest restores a verified Pre-Mutation Snapshot.
type RestoreRequest struct {
	Target         TargetSpec `json:"target"`
	SnapshotID     string     `json:"snapshot_id"`
	ExpectedSHA256 string     `json:"expected_sha256,omitempty"`
}

// RestoreResult reports atomic rollback outcome.
type RestoreResult struct {
	OK           bool   `json:"ok"`
	SnapshotID   string `json:"snapshot_id"`
	TableName    string `json:"table_name"`
	RestoredRows string `json:"restored_rows"`
	Status       string `json:"status"`
}

// Inspector performs loopback-tunneled and workspace-confined SQL inspection and guarded mutations.
type Inspector struct {
	sqliteRoot string
	tunnels    *gssh.TunnelManager
}

// NewInspector creates an Inspector bound to a confined SQLite storage root and active TunnelManager.
func NewInspector(sqliteRoot string, tunnels *gssh.TunnelManager) *Inspector {
	cleanRoot := strings.TrimSpace(sqliteRoot)
	if cleanRoot == "" {
		cleanRoot = "storage"
	}
	return &Inspector{sqliteRoot: cleanRoot, tunnels: tunnels}
}

func (in *Inspector) openTarget(target TargetSpec, readOnly bool) (*sql.DB, string, string, error) {
	if strings.TrimSpace(target.DirectHost) != "" {
		return nil, "", "", newErr(422, ErrValidation, "direct host DB connections are blocked; use an active 127.0.0.1 SSH tunnel or confined local SQLite")
	}
	engine := NormalizeEngine(target.Engine)
	switch engine {
	case "sqlite":
		resolved, err := ResolveConfinedSQLite(in.sqliteRoot, target.SQLitePath)
		if err != nil {
			return nil, "", "", err
		}
		info, statErr := os.Stat(resolved)
		if statErr != nil || info.IsDir() {
			return nil, "", "", newErr(404, ErrConfinement, "SQLite database file not found in confined storage root")
		}
		uri := "file:" + filepath.ToSlash(resolved) + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
		if readOnly {
			uri += "&mode=ro&_pragma=query_only(1)"
		}
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			return nil, "", "", newErr(500, ErrValidation, fmt.Sprintf("open sqlite failed: %v", err))
		}
		db.SetMaxOpenConns(1)
		return db, engine, filepath.Base(resolved), nil

	case "postgres", "mariadb":
		tunID := strings.TrimSpace(target.TunnelID)
		if tunID == "" {
			return nil, "", "", newErr(422, ErrValidation, "tunnel_id is required for remote PostgreSQL/MariaDB inspection (zero public DB ports)")
		}
		if in.tunnels == nil {
			return nil, "", "", newErr(422, ErrValidation, "tunnel manager unavailable")
		}
		tun, ok := in.tunnels.GetTunnel(tunID)
		if !ok {
			return nil, "", "", newErr(422, ErrValidation, fmt.Sprintf("active 127.0.0.1 SSH tunnel %q not found or closed", tunID))
		}
		if _, err := gssh.ValidateLoopbackBind(tun.LocalAddr); err != nil {
			return nil, "", "", newErr(403, gssh.ErrLoopbackRequired, err.Error())
		}
		tunEng := NormalizeEngine(tun.Engine)
		if tunEng != engine {
			return nil, "", "", newErr(422, ErrValidation, fmt.Sprintf("tunnel %q engine is %q, requested %q", tunID, tunEng, engine))
		}
		loopAddr := net.JoinHostPort("127.0.0.1", tun.LocalPort)
		dbName := strings.TrimSpace(target.DBName)
		user := strings.TrimSpace(target.DBUser)

		if engine == "postgres" {
			if dbName == "" {
				dbName = "postgres"
			}
			if user == "" {
				user = "postgres"
			}
			u := &url.URL{
				Scheme: "postgres",
				User:   url.UserPassword(user, target.DBPassword),
				Host:   loopAddr,
				Path:   "/" + dbName,
			}
			q := u.Query()
			q.Set("sslmode", "disable")
			q.Set("connect_timeout", "5")
			u.RawQuery = q.Encode()
			db, err := sql.Open("pgx", u.String())
			if err != nil {
				return nil, "", "", newErr(502, ErrValidation, fmt.Sprintf("open tunneled postgres failed: %v", err))
			}
			return db, engine, fmt.Sprintf("pg@%s (%s)", loopAddr, dbName), nil
		}

		// MariaDB / MySQL strictly over 127.0.0.1:<tunnelPort>
		if user == "" {
			user = "root"
		}
		cfg := mysql.NewConfig()
		cfg.Net = "tcp"
		cfg.Addr = loopAddr
		cfg.User = user
		cfg.Passwd = target.DBPassword
		cfg.DBName = dbName
		cfg.Timeout = 5 * time.Second
		cfg.ReadTimeout = queryTimeout
		cfg.WriteTimeout = queryTimeout
		cfg.ParseTime = false
		db, err := sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			return nil, "", "", newErr(502, ErrValidation, fmt.Sprintf("open tunneled mariadb failed: %v", err))
		}
		return db, engine, fmt.Sprintf("mariadb@%s (%s)", loopAddr, dbName), nil

	default:
		return nil, "", "", newErr(422, ErrValidation, fmt.Sprintf("unsupported database engine %q", target.Engine))
	}
}

func errorStatus(err error) int {
	if ie, ok := err.(*InspectorError); ok {
		return ie.HTTPStatus
	}
	return 500
}

// InspectSchema lists databases, tables, columns, indexes, foreign keys, and exact row counts.
func (in *Inspector) InspectSchema(ctx context.Context, target TargetSpec) (*SchemaResult, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	db, engine, label, err := in.openTarget(target, true)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	res := &SchemaResult{
		OK:          true,
		Engine:      engine,
		TargetLabel: label,
		Databases:   []string{},
		Tables:      []TableSchema{},
	}

	switch engine {
	case "sqlite":
		res.Databases = []string{"main"}
		err = inspectSQLiteSchema(qCtx, db, res)
	case "postgres":
		err = inspectPostgresSchema(qCtx, db, strings.TrimSpace(target.SchemaName), res)
	case "mariadb":
		err = inspectMariaDBSchema(qCtx, db, strings.TrimSpace(target.DBName), res)
	}
	if err != nil {
		return nil, errorStatus(err), newErr(502, ErrValidation, fmt.Sprintf("schema introspection failed: %v", err))
	}
	return res, 200, nil
}

func inspectSQLiteSchema(ctx context.Context, db *sql.DB, res *SchemaResult) error {
	tRows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name ASC`,
	)
	if err != nil {
		return err
	}
	var tableNames []string
	for tRows.Next() {
		var tName string
		if sErr := tRows.Scan(&tName); sErr == nil && ValidateIdentifier(tName) == nil {
			tableNames = append(tableNames, tName)
		}
	}
	_ = tRows.Close()

	for _, tName := range tableNames {
		quoted, err := QuoteIdent("sqlite", tName)
		if err != nil {
			continue
		}
		var countVal int64
		_ = db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, quoted)).Scan(&countVal)

		tSchema := TableSchema{
			Name:        tName,
			Schema:      "main",
			RowCount:    strconv.FormatInt(countVal, 10),
			Columns:     []ColumnMeta{},
			Indexes:     []IndexMeta{},
			ForeignKeys: []ForeignKeyMeta{},
		}

		colRows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, quoted))
		if err == nil {
			for colRows.Next() {
				var cid, notnull, pk int
				var cname, ctype string
				var dflt sql.NullString
				if sErr := colRows.Scan(&cid, &cname, &ctype, &notnull, &dflt, &pk); sErr == nil {
					tSchema.Columns = append(tSchema.Columns, ColumnMeta{
						Name:       cname,
						Type:       ctype,
						Nullable:   notnull == 0,
						PrimaryKey: pk > 0,
						DefaultVal: dflt.String,
					})
				}
			}
			_ = colRows.Close()
		}

		idxListRows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA index_list(%s)`, quoted))
		if err == nil {
			var idxMeta []struct {
				name   string
				unique bool
			}
			for idxListRows.Next() {
				var seq, unique int
				var idxName, origin string
				var partial int
				if sErr := idxListRows.Scan(&seq, &idxName, &unique, &origin, &partial); sErr == nil {
					if ValidateIdentifier(idxName) == nil {
						idxMeta = append(idxMeta, struct {
							name   string
							unique bool
						}{name: idxName, unique: unique != 0})
					}
				}
			}
			_ = idxListRows.Close()
			for _, im := range idxMeta {
				qIdx, qErr := QuoteIdent("sqlite", im.name)
				if qErr != nil {
					continue
				}
				var cols []string
				iiRows, iiErr := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA index_info(%s)`, qIdx))
				if iiErr == nil {
					for iiRows.Next() {
						var seqno, cid int
						var cname sql.NullString
						if iiRows.Scan(&seqno, &cid, &cname) == nil && cname.Valid {
							cols = append(cols, cname.String)
						}
					}
					_ = iiRows.Close()
				}
				tSchema.Indexes = append(tSchema.Indexes, IndexMeta{Name: im.name, Unique: im.unique, Columns: cols})
			}
		}

		fkRows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA foreign_key_list(%s)`, quoted))
		if err == nil {
			for fkRows.Next() {
				var id, seq int
				var tableRef, fromCol, toCol, onUpd, onDel, match string
				if fkRows.Scan(&id, &seq, &tableRef, &fromCol, &toCol, &onUpd, &onDel, &match) == nil {
					tSchema.ForeignKeys = append(tSchema.ForeignKeys, ForeignKeyMeta{
						Column:    fromCol,
						RefTable:  tableRef,
						RefColumn: toCol,
						OnUpdate:  onUpd,
						OnDelete:  onDel,
					})
				}
			}
			_ = fkRows.Close()
		}
		res.Tables = append(res.Tables, tSchema)
	}
	return nil
}

func inspectPostgresSchema(ctx context.Context, db *sql.DB, schemaName string, res *SchemaResult) error {
	if schemaName == "" {
		schemaName = "public"
	} else if err := ValidateIdentifier(schemaName); err != nil {
		return err
	}

	dbRows, err := db.QueryContext(ctx, `SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname ASC`)
	if err == nil {
		for dbRows.Next() {
			var dn string
			if dbRows.Scan(&dn) == nil {
				res.Databases = append(res.Databases, dn)
			}
		}
		_ = dbRows.Close()
	}

	tRows, err := db.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY table_name ASC`,
		schemaName,
	)
	if err != nil {
		return err
	}
	var tableNames []string
	for tRows.Next() {
		var tn string
		if tRows.Scan(&tn) == nil && ValidateIdentifier(tn) == nil {
			tableNames = append(tableNames, tn)
		}
	}
	_ = tRows.Close()

	for _, tName := range tableNames {
		qSchema, _ := QuoteIdent("postgres", schemaName)
		qTable, _ := QuoteIdent("postgres", tName)
		var countVal int64
		_ = db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count(*) FROM %s.%s`, qSchema, qTable)).Scan(&countVal)

		tSchema := TableSchema{
			Name:        tName,
			Schema:      schemaName,
			RowCount:    strconv.FormatInt(countVal, 10),
			Columns:     []ColumnMeta{},
			Indexes:     []IndexMeta{},
			ForeignKeys: []ForeignKeyMeta{},
		}
		cRows, cErr := db.QueryContext(ctx,
			`SELECT column_name, data_type, is_nullable, COALESCE(column_default, '') FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position ASC`,
			schemaName, tName,
		)
		if cErr == nil {
			for cRows.Next() {
				var cn, dt, isNull, dflt string
				if cRows.Scan(&cn, &dt, &isNull, &dflt) == nil {
					tSchema.Columns = append(tSchema.Columns, ColumnMeta{
						Name:       cn,
						Type:       dt,
						Nullable:   strings.EqualFold(isNull, "YES"),
						DefaultVal: dflt,
					})
				}
			}
			_ = cRows.Close()
		}
		res.Tables = append(res.Tables, tSchema)
	}
	return nil
}

func inspectMariaDBSchema(ctx context.Context, db *sql.DB, dbName string, res *SchemaResult) error {
	dbRows, err := db.QueryContext(ctx, `SELECT schema_name FROM information_schema.schemata ORDER BY schema_name ASC`)
	if err == nil {
		for dbRows.Next() {
			var dn string
			if dbRows.Scan(&dn) == nil {
				res.Databases = append(res.Databases, dn)
			}
		}
		_ = dbRows.Close()
	}

	targetDB := dbName
	if targetDB == "" {
		_ = db.QueryRowContext(ctx, `SELECT DATABASE()`).Scan(&targetDB)
	}
	if targetDB == "" {
		return nil
	}
	if err := ValidateIdentifier(targetDB); err != nil {
		return err
	}

	tRows, err := db.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables WHERE table_schema = ? AND table_type = 'BASE TABLE' ORDER BY table_name ASC`,
		targetDB,
	)
	if err != nil {
		return err
	}
	var tableNames []string
	for tRows.Next() {
		var tn string
		if tRows.Scan(&tn) == nil && ValidateIdentifier(tn) == nil {
			tableNames = append(tableNames, tn)
		}
	}
	_ = tRows.Close()

	for _, tName := range tableNames {
		qDB, _ := QuoteIdent("mariadb", targetDB)
		qTbl, _ := QuoteIdent("mariadb", tName)
		var countVal int64
		_ = db.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s.%s", qDB, qTbl)).Scan(&countVal)

		tSchema := TableSchema{
			Name:        tName,
			Schema:      targetDB,
			RowCount:    strconv.FormatInt(countVal, 10),
			Columns:     []ColumnMeta{},
			Indexes:     []IndexMeta{},
			ForeignKeys: []ForeignKeyMeta{},
		}
		cRows, cErr := db.QueryContext(ctx,
			`SELECT column_name, column_type, is_nullable, column_key, COALESCE(column_default, '') FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position ASC`,
			targetDB, tName,
		)
		if cErr == nil {
			for cRows.Next() {
				var cn, ct, isNull, cKey, dflt string
				if cRows.Scan(&cn, &ct, &isNull, &cKey, &dflt) == nil {
					tSchema.Columns = append(tSchema.Columns, ColumnMeta{
						Name:       cn,
						Type:       ct,
						Nullable:   strings.EqualFold(isNull, "YES"),
						PrimaryKey: strings.EqualFold(cKey, "PRI"),
						DefaultVal: dflt,
					})
				}
			}
			_ = cRows.Close()
		}
		res.Tables = append(res.Tables, tSchema)
	}
	return nil
}

func (in *Inspector) loadTableColumnSet(ctx context.Context, target TargetSpec, tableName string) (map[string]bool, error) {
	schemaRes, _, err := in.InspectSchema(ctx, target)
	if err != nil {
		return nil, err
	}
	for _, tbl := range schemaRes.Tables {
		if tbl.Name == tableName {
			out := make(map[string]bool, len(tbl.Columns))
			for _, col := range tbl.Columns {
				out[col.Name] = true
			}
			return out, nil
		}
	}
	return nil, newErr(404, ErrValidation, fmt.Sprintf("table %q not found in database", tableName))
}

// BrowseRows returns a paginated page of rows (<= 100) using strictly parameterized filter & allowlisted identifiers.
func (in *Inspector) BrowseRows(ctx context.Context, req RowsRequest) (*RowsResult, int, error) {
	if err := ValidateIdentifier(req.Table); err != nil {
		return nil, errorStatus(err), err
	}
	page, limit, err := ValidatePageLimit(req.Page, req.Limit)
	if err != nil {
		return nil, errorStatus(err), err
	}

	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	colSet, err := in.loadTableColumnSet(qCtx, req.Target, req.Table)
	if err != nil {
		return nil, errorStatus(err), err
	}

	db, engine, _, err := in.openTarget(req.Target, true)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	qTable, err := QuoteIdent(engine, req.Table)
	if err != nil {
		return nil, errorStatus(err), err
	}

	var whereClause string
	var args []any
	nextParamIdx := 1
	ph := func() string {
		if engine == "postgres" {
			s := fmt.Sprintf("$%d", nextParamIdx)
			nextParamIdx++
			return s
		}
		return "?"
	}

	filterCol := strings.TrimSpace(req.FilterCol)
	if filterCol != "" {
		if err := ValidateIdentifier(filterCol); err != nil {
			return nil, errorStatus(err), err
		}
		if !colSet[filterCol] {
			return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("filter_col %q does not exist on table %q", filterCol, req.Table))
		}
		qCol, _ := QuoteIdent(engine, filterCol)
		op := strings.ToLower(strings.TrimSpace(req.FilterOp))
		if op == "" {
			op = "contains"
		}
		switch op {
		case "eq":
			whereClause = fmt.Sprintf(" WHERE CAST(%s AS TEXT) = %s", qCol, ph())
			if engine == "mariadb" {
				whereClause = fmt.Sprintf(" WHERE CAST(%s AS CHAR) = %s", qCol, ph())
			}
			args = append(args, req.FilterVal)
		case "contains":
			if engine == "mariadb" {
				whereClause = fmt.Sprintf(" WHERE CAST(%s AS CHAR) LIKE %s", qCol, ph())
			} else {
				whereClause = fmt.Sprintf(" WHERE CAST(%s AS TEXT) LIKE %s", qCol, ph())
			}
			args = append(args, "%"+req.FilterVal+"%")
		case "starts_with":
			if engine == "mariadb" {
				whereClause = fmt.Sprintf(" WHERE CAST(%s AS CHAR) LIKE %s", qCol, ph())
			} else {
				whereClause = fmt.Sprintf(" WHERE CAST(%s AS TEXT) LIKE %s", qCol, ph())
			}
			args = append(args, req.FilterVal+"%")
		case "gt":
			whereClause = fmt.Sprintf(" WHERE %s > %s", qCol, ph())
			args = append(args, req.FilterVal)
		case "lt":
			whereClause = fmt.Sprintf(" WHERE %s < %s", qCol, ph())
			args = append(args, req.FilterVal)
		default:
			return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("unsupported filter_op %q", req.FilterOp))
		}
	}

	var orderClause string
	sortCol := strings.TrimSpace(req.SortCol)
	if sortCol != "" {
		if err := ValidateIdentifier(sortCol); err != nil {
			return nil, errorStatus(err), err
		}
		if !colSet[sortCol] {
			return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("sort_col %q does not exist on table %q", sortCol, req.Table))
		}
		qSort, _ := QuoteIdent(engine, sortCol)
		dir := strings.ToUpper(strings.TrimSpace(req.SortDir))
		if dir != "DESC" {
			dir = "ASC"
		}
		orderClause = fmt.Sprintf(" ORDER BY %s %s", qSort, dir)
	}

	countSQL := fmt.Sprintf("SELECT count(*) FROM %s%s", qTable, whereClause)
	var totalRows int64
	if err := db.QueryRowContext(qCtx, countSQL, args...).Scan(&totalRows); err != nil {
		return nil, 502, newErr(502, ErrValidation, fmt.Sprintf("row count query failed: %v", err))
	}

	offset := (page - 1) * limit
	dataArgs := append(append([]any{}, args...), limit, offset)
	dataSQL := fmt.Sprintf("SELECT * FROM %s%s%s LIMIT %s OFFSET %s", qTable, whereClause, orderClause, ph(), ph())

	rows, err := db.QueryContext(qCtx, dataSQL, dataArgs...)
	if err != nil {
		return nil, 502, newErr(502, ErrValidation, fmt.Sprintf("row browse query failed: %v", err))
	}
	defer rows.Close()

	cols, records, _, _, err := ScanRows(rows, limit)
	if err != nil {
		return nil, 500, newErr(500, ErrValidation, fmt.Sprintf("row scan failed: %v", err))
	}

	totalPages := int64(1)
	if totalRows > 0 {
		totalPages = (totalRows + int64(limit) - 1) / int64(limit)
	}
	return &RowsResult{
		OK:         true,
		Engine:     engine,
		Table:      req.Table,
		Page:       strconv.Itoa(page),
		Limit:      strconv.Itoa(limit),
		TotalRows:  strconv.FormatInt(totalRows, 10),
		TotalPages: strconv.FormatInt(totalPages, 10),
		Columns:    cols,
		Rows:       records,
	}, 200, nil
}

// RunReadOnlyQuery executes strictly single-statement read-only SQL (SELECT/SHOW/DESCRIBE/EXPLAIN) in read-only mode.
func (in *Inspector) RunReadOnlyQuery(ctx context.Context, req QueryRequest) (*QueryResult, int, error) {
	classified, err := ClassifySQL(req.SQL)
	if err != nil {
		return nil, errorStatus(err), err
	}
	if classified.Kind != KindReadOnly {
		return nil, 403, newErr(403, ErrForbiddenQuery,
			fmt.Sprintf("read-only runner blocked %s statement; route writes/DDL through Plan -> Pre-Mutation Snapshot -> Execute", classified.Verb))
	}

	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	db, engine, _, err := in.openTarget(req.Target, true)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	var rows *sql.Rows
	if engine == "sqlite" {
		conn, cErr := db.Conn(qCtx)
		if cErr != nil {
			return nil, 500, cErr
		}
		defer conn.Close()
		if _, pErr := conn.ExecContext(qCtx, "PRAGMA query_only = ON"); pErr != nil {
			return nil, 500, pErr
		}
		rows, err = conn.QueryContext(qCtx, classified.Statements[0])
		if err != nil {
			return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("query error: %v", err))
		}
		defer rows.Close()
		cols, records, _, truncated, sErr := ScanRows(rows, MaxRowsPerPage)
		if sErr != nil {
			return nil, 500, sErr
		}
		return &QueryResult{
			OK:        true,
			Engine:    engine,
			Verb:      classified.Verb,
			ReadOnly:  true,
			Truncated: truncated,
			RowCount:  strconv.Itoa(len(records)),
			Columns:   cols,
			Rows:      records,
		}, 200, nil
	}

	tx, err := db.BeginTx(qCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 502, newErr(502, ErrValidation, fmt.Sprintf("failed to open read-only transaction: %v", err))
	}
	defer func() { _ = tx.Rollback() }()

	rows, err = tx.QueryContext(qCtx, classified.Statements[0])
	if err != nil {
		return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("query error: %v", err))
	}
	defer rows.Close()
	cols, records, _, truncated, err := ScanRows(rows, MaxRowsPerPage)
	if err != nil {
		return nil, 500, err
	}
	return &QueryResult{
		OK:        true,
		Engine:    engine,
		Verb:      classified.Verb,
		ReadOnly:  true,
		Truncated: truncated,
		RowCount:  strconv.Itoa(len(records)),
		Columns:   cols,
		Rows:      records,
	}, 200, nil
}

// PlanMutation classifies write/DDL/import SQL and creates an automatic Pre-Mutation Snapshot before execution.
func (in *Inspector) PlanMutation(ctx context.Context, req MutatePlanRequest) (*MutatePlanResult, int, error) {
	classified, err := ClassifySQL(req.SQL)
	if err != nil {
		return nil, errorStatus(err), err
	}
	if classified.Kind == KindReadOnly {
		return nil, 422, newErr(422, ErrValidation, "read-only queries do not require mutation approval; execute via Read-Only Query Runner")
	}

	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	db, engine, _, err := in.openTarget(req.Target, false)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	targetID := strings.TrimSpace(req.Target.TargetID)
	if targetID == "" {
		targetID = engine
	}

	snap, relPath, err := capturePreMutationSnapshot(qCtx, db, engine, targetID, classified.TableName, in.sqliteRoot)
	if err != nil {
		return nil, errorStatus(err), newErr(500, ErrValidation, fmt.Sprintf("pre-mutation snapshot capture failed: %v", err))
	}

	return &MutatePlanResult{
		OK:             true,
		Engine:         engine,
		Kind:           string(classified.Kind),
		Verb:           classified.Verb,
		TableName:      classified.TableName,
		StatementCount: strconv.Itoa(len(classified.Statements)),
		PlainSummary: fmt.Sprintf("%s — Pre-Mutation Snapshot %s captured (%s existing rows, SHA-256 verified).",
			classified.Summary, snap.SnapshotID, snap.RowCount),
		SnapshotID:   snap.SnapshotID,
		SnapshotPath: relPath,
		BackupSHA256: snap.PayloadSHA256,
		PreRowCount:  snap.RowCount,
	}, 200, nil
}

// ExecuteMutation runs an approved DML/DDL/import plan transactionally.
func (in *Inspector) ExecuteMutation(ctx context.Context, req MutateExecuteRequest) (*MutateExecuteResult, int, error) {
	classified, err := ClassifySQL(req.SQL)
	if err != nil {
		return nil, errorStatus(err), err
	}
	if classified.Kind == KindReadOnly {
		return nil, 422, newErr(422, ErrValidation, "read-only queries must use the Read-Only Query Runner")
	}

	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	db, engine, _, err := in.openTarget(req.Target, false)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	tx, err := db.BeginTx(qCtx, nil)
	if err != nil {
		return nil, 502, newErr(502, ErrValidation, fmt.Sprintf("begin transaction failed: %v", err))
	}
	defer func() { _ = tx.Rollback() }()

	var affectedTotal int64
	for _, stmt := range classified.Statements {
		res, execErr := tx.ExecContext(qCtx, stmt)
		if execErr != nil {
			return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("mutation failed cleanly and rolled back: %v", execErr))
		}
		if n, aErr := res.RowsAffected(); aErr == nil && n > 0 {
			affectedTotal += n
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 500, newErr(500, ErrValidation, fmt.Sprintf("commit failed: %v", err))
	}

	return &MutateExecuteResult{
		OK:                 true,
		Engine:             engine,
		Kind:               string(classified.Kind),
		Verb:               classified.Verb,
		TableName:          classified.TableName,
		StatementsExecuted: strconv.Itoa(len(classified.Statements)),
		AffectedRows:       strconv.FormatInt(affectedTotal, 10),
		SnapshotID:         strings.TrimSpace(req.SnapshotID),
	}, 200, nil
}

// ExportSQL exports sanitized CREATE TABLE + batched INSERT SQL statements over a read-only connection.
func (in *Inspector) ExportSQL(ctx context.Context, req ExportRequest) (*ExportResult, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	schemaRes, status, err := in.InspectSchema(qCtx, req.Target)
	if err != nil {
		return nil, status, err
	}
	db, engine, label, err := in.openTarget(req.Target, true)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	selected := make([]TableSchema, 0)
	reqTable := strings.TrimSpace(req.Table)
	if reqTable != "" {
		if err := ValidateIdentifier(reqTable); err != nil {
			return nil, errorStatus(err), err
		}
		found := false
		for _, t := range schemaRes.Tables {
			if t.Name == reqTable {
				selected = append(selected, t)
				found = true
				break
			}
		}
		if !found {
			return nil, 404, newErr(404, ErrValidation, fmt.Sprintf("table %q not found", reqTable))
		}
	} else {
		selected = append(selected, schemaRes.Tables...)
	}

	var dump strings.Builder
	dump.WriteString(fmt.Sprintf("-- Gashboard v0.2.0 SQL Export (%s / %s)\n", engine, label))
	dump.WriteString(fmt.Sprintf("-- GeneratedAt: %s\n\n", time.Now().UTC().Format(time.RFC3339)))

	totalExportedRows := 0
	for _, tbl := range selected {
		if engine == "sqlite" {
			var ddl sql.NullString
			if err := db.QueryRowContext(qCtx, `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, tbl.Name).Scan(&ddl); err == nil && ddl.Valid {
				dump.WriteString(ddl.String + ";\n")
			}
		}
		qTbl, err := QuoteIdent(engine, tbl.Name)
		if err != nil {
			continue
		}
		rows, err := db.QueryContext(qCtx, fmt.Sprintf("SELECT * FROM %s LIMIT %d", qTbl, maxSnapshotCaptureRows))
		if err != nil {
			continue
		}
		cols, _, typedRows, _, sErr := ScanRows(rows, maxSnapshotCaptureRows)
		_ = rows.Close()
		if sErr != nil || len(typedRows) == 0 {
			dump.WriteString("\n")
			continue
		}
		qCols := make([]string, len(cols))
		for i, c := range cols {
			qc, _ := QuoteIdent(engine, c.Name)
			qCols[i] = qc
		}
		colList := strings.Join(qCols, ", ")
		for _, row := range typedRows {
			vals := make([]string, len(row))
			for i, cell := range row {
				vals[i] = formatSQLLiteral(cell)
			}
			dump.WriteString(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s);\n", qTbl, colList, strings.Join(vals, ", ")))
			totalExportedRows++
		}
		dump.WriteString("\n")
	}

	dumpStr := dump.String()
	sum := sha256.Sum256([]byte(dumpStr))
	sumHex := "sha256:" + hex.EncodeToString(sum[:])

	var exportRel string
	if req.SaveFile {
		fname := strings.TrimSpace(req.Filename)
		if fname == "" {
			fname = "export_" + strconv.FormatInt(time.Now().UTC().Unix(), 10) + ".sql"
		}
		if strings.Contains(fname, "/") || strings.Contains(fname, `\`) || strings.Contains(fname, "..") || !strings.HasSuffix(strings.ToLower(fname), ".sql") {
			return nil, 403, newErr(403, ErrConfinement, "export filename must be a single .sql filename without traversal")
		}
		absRoot, _ := filepath.Abs(in.sqliteRoot)
		expDir := filepath.Join(absRoot, "exports")
		if err := os.MkdirAll(expDir, 0o700); err != nil {
			return nil, 500, err
		}
		targetFile := filepath.Join(expDir, fname)
		if !isWithinDir(expDir, targetFile) {
			return nil, 403, newErr(403, ErrConfinement, "export file path escaped exports directory")
		}
		if err := os.WriteFile(targetFile, []byte(dumpStr), 0o600); err != nil {
			return nil, 500, err
		}
		exportRel = filepath.ToSlash(filepath.Join("exports", fname))
	}

	return &ExportResult{
		OK:         true,
		Engine:     engine,
		SQLDump:    dumpStr,
		ExportPath: exportRel,
		SHA256:     sumHex,
		TableCount: strconv.Itoa(len(selected)),
		RowCount:   strconv.Itoa(totalExportedRows),
	}, 200, nil
}

func formatSQLLiteral(c TypedCell) string {
	switch c.Kind {
	case "null":
		return "NULL"
	case "int", "real":
		if IsExactDecimalWire(c.Value) {
			return c.Value
		}
		return "'" + strings.ReplaceAll(c.Value, "'", "''") + "'"
	case "blob":
		return "'" + strings.ReplaceAll(c.Value, "'", "''") + "'"
	default:
		return "'" + strings.ReplaceAll(c.Value, "'", "''") + "'"
	}
}

// RestoreSnapshot verifies SHA-256 and atomically restores a Pre-Mutation Snapshot.
func (in *Inspector) RestoreSnapshot(ctx context.Context, req RestoreRequest) (*RestoreResult, int, error) {
	qCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	snap, err := loadVerifiedSnapshot(in.sqliteRoot, req.SnapshotID, req.ExpectedSHA256)
	if err != nil {
		return nil, errorStatus(err), err
	}
	db, engine, _, err := in.openTarget(req.Target, false)
	if err != nil {
		return nil, errorStatus(err), err
	}
	defer db.Close()

	if snap.Engine != "" && snap.Engine != engine {
		return nil, 422, newErr(422, ErrValidation, fmt.Sprintf("snapshot engine %q does not match target engine %q", snap.Engine, engine))
	}

	restoredRows, err := applyTableSnapshotRestore(qCtx, db, engine, snap)
	if err != nil {
		return nil, errorStatus(err), newErr(500, ErrValidation, fmt.Sprintf("snapshot restore failed cleanly: %v", err))
	}
	return &RestoreResult{
		OK:           true,
		SnapshotID:   snap.SnapshotID,
		TableName:    snap.TableName,
		RestoredRows: strconv.Itoa(restoredRows),
		Status:       "restored",
	}, 200, nil
}
