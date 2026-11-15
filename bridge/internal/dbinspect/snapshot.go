package dbinspect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxSnapshotCaptureRows = 10000

// TableSnapshot captures pre-mutation DDL and exact typed row data with SHA-256 tamper protection.
type TableSnapshot struct {
	SnapshotID    string        `json:"snapshot_id"`
	TargetID      string        `json:"target_id"`
	Engine        string        `json:"engine"`
	TableName     string        `json:"table_name"`
	ExistedBefore bool          `json:"existed_before"`
	CreateSQL     string        `json:"create_sql"`
	IndexSQLs     []string      `json:"index_sqls"`
	Columns       []string      `json:"columns"`
	Rows          [][]TypedCell `json:"rows"`
	RowCount      string        `json:"row_count"`
	CreatedAt     string        `json:"created_at"`
	PayloadSHA256 string        `json:"payload_sha256"`
}

func randomHexID(prefix string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func (s *TableSnapshot) computePayloadDigest() (string, error) {
	clone := *s
	clone.PayloadSHA256 = ""
	raw, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func snapshotsDir(sqliteRoot string) (string, error) {
	rootClean := strings.TrimSpace(sqliteRoot)
	if rootClean == "" {
		rootClean = "storage"
	}
	absRoot, err := filepath.Abs(rootClean)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(absRoot, "snapshots")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

var safeSnapshotIDRegex = strings.NewReplacer("/", "", "\\", "", "..", "")

func resolveSnapshotFile(sqliteRoot, snapshotID string) (string, error) {
	cleanID := strings.TrimSpace(snapshotID)
	if err := ValidateIdentifier(cleanID); err != nil {
		return "", newErr(403, ErrConfinement, "invalid snapshot identifier")
	}
	dir, err := snapshotsDir(sqliteRoot)
	if err != nil {
		return "", err
	}
	cand := filepath.Join(dir, cleanID+".json")
	if !isWithinDir(dir, cand) {
		return "", newErr(403, ErrConfinement, "snapshot path escaped snapshots directory")
	}
	_ = safeSnapshotIDRegex
	return cand, nil
}

// capturePreMutationSnapshot records the affected table DDL and rows before mutation executes.
func capturePreMutationSnapshot(ctx context.Context, db *sql.DB, engine, targetID, tableName, sqliteRoot string) (TableSnapshot, string, error) {
	snapID, err := randomHexID("dbsnap_")
	if err != nil {
		return TableSnapshot{}, "", err
	}
	snap := TableSnapshot{
		SnapshotID: snapID,
		TargetID:   targetID,
		Engine:     NormalizeEngine(engine),
		TableName:  strings.TrimSpace(tableName),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	if snap.TableName != "" {
		if err := ValidateIdentifier(snap.TableName); err != nil {
			return TableSnapshot{}, "", err
		}
		switch snap.Engine {
		case "sqlite":
			if err := captureSQLiteTable(ctx, db, &snap); err != nil {
				return TableSnapshot{}, "", err
			}
		case "postgres":
			if err := capturePostgresTable(ctx, db, &snap); err != nil {
				return TableSnapshot{}, "", err
			}
		case "mariadb":
			if err := captureMariaDBTable(ctx, db, &snap); err != nil {
				return TableSnapshot{}, "", err
			}
		}
	}
	snap.RowCount = strconv.Itoa(len(snap.Rows))

	digest, err := snap.computePayloadDigest()
	if err != nil {
		return TableSnapshot{}, "", err
	}
	snap.PayloadSHA256 = digest

	snapPath, err := resolveSnapshotFile(sqliteRoot, snapID)
	if err != nil {
		return TableSnapshot{}, "", err
	}
	encoded, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return TableSnapshot{}, "", err
	}
	if err := os.WriteFile(snapPath, encoded, 0o600); err != nil {
		return TableSnapshot{}, "", err
	}
	relPath := filepath.ToSlash(filepath.Join("snapshots", snapID+".json"))
	return snap, relPath, nil
}

func captureSQLiteTable(ctx context.Context, db *sql.DB, snap *TableSnapshot) error {
	var createSQL sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`,
		snap.TableName,
	).Scan(&createSQL)
	if err == sql.ErrNoRows {
		snap.ExistedBefore = false
		return nil
	}
	if err != nil {
		return err
	}
	snap.ExistedBefore = true
	snap.CreateSQL = createSQL.String

	idxRows, err := db.QueryContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL`,
		snap.TableName,
	)
	if err != nil {
		return err
	}
	defer idxRows.Close()
	for idxRows.Next() {
		var idxSQL string
		if scanErr := idxRows.Scan(&idxSQL); scanErr == nil && strings.TrimSpace(idxSQL) != "" {
			snap.IndexSQLs = append(snap.IndexSQLs, idxSQL)
		}
	}

	quoted, err := QuoteIdent("sqlite", snap.TableName)
	if err != nil {
		return err
	}
	dataRows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT * FROM %s`, quoted))
	if err != nil {
		return err
	}
	defer dataRows.Close()

	cols, _, typedRows, truncated, err := ScanRows(dataRows, maxSnapshotCaptureRows)
	if err != nil {
		return err
	}
	if truncated {
		return newErr(422, ErrValidation, fmt.Sprintf("table %s exceeds max automatic pre-mutation snapshot cap (%d rows); export dump manually first", snap.TableName, maxSnapshotCaptureRows))
	}
	for _, c := range cols {
		snap.Columns = append(snap.Columns, c.Name)
	}
	snap.Rows = typedRows
	return nil
}

func capturePostgresTable(ctx context.Context, db *sql.DB, snap *TableSnapshot) error {
	var exists int
	err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1`,
		snap.TableName,
	).Scan(&exists)
	if err != nil || exists == 0 {
		snap.ExistedBefore = false
		return err
	}
	snap.ExistedBefore = true
	quoted, err := QuoteIdent("postgres", snap.TableName)
	if err != nil {
		return err
	}
	dataRows, err := db.QueryContext(ctx, fmt.Sprintf(`SELECT * FROM %s`, quoted))
	if err != nil {
		return err
	}
	defer dataRows.Close()
	cols, _, typedRows, truncated, err := ScanRows(dataRows, maxSnapshotCaptureRows)
	if err != nil {
		return err
	}
	if truncated {
		return newErr(422, ErrValidation, fmt.Sprintf("table %s exceeds max automatic pre-mutation snapshot cap (%d rows)", snap.TableName, maxSnapshotCaptureRows))
	}
	for _, c := range cols {
		snap.Columns = append(snap.Columns, c.Name)
	}
	snap.Rows = typedRows
	return nil
}

func captureMariaDBTable(ctx context.Context, db *sql.DB, snap *TableSnapshot) error {
	var tName, ddl string
	err := db.QueryRowContext(ctx, fmt.Sprintf("SHOW CREATE TABLE `%s`", snap.TableName)).Scan(&tName, &ddl)
	if err != nil {
		snap.ExistedBefore = false
		return nil
	}
	snap.ExistedBefore = true
	snap.CreateSQL = ddl
	quoted, err := QuoteIdent("mariadb", snap.TableName)
	if err != nil {
		return err
	}
	dataRows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT * FROM %s", quoted))
	if err != nil {
		return err
	}
	defer dataRows.Close()
	cols, _, typedRows, truncated, err := ScanRows(dataRows, maxSnapshotCaptureRows)
	if err != nil {
		return err
	}
	if truncated {
		return newErr(422, ErrValidation, fmt.Sprintf("table %s exceeds max automatic pre-mutation snapshot cap (%d rows)", snap.TableName, maxSnapshotCaptureRows))
	}
	for _, c := range cols {
		snap.Columns = append(snap.Columns, c.Name)
	}
	snap.Rows = typedRows
	return nil
}

// loadVerifiedSnapshot reads and SHA-256 checks a Pre-Mutation Snapshot from snapshotsDir.
func loadVerifiedSnapshot(sqliteRoot, snapshotID, expectedSHA256 string) (*TableSnapshot, error) {
	snapPath, err := resolveSnapshotFile(sqliteRoot, snapshotID)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(snapPath)
	if err != nil {
		return nil, newErr(404, ErrConfinement, "Pre-Mutation Snapshot file not found")
	}
	var snap TableSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, newErr(422, ErrValidation, "corrupt Pre-Mutation Snapshot JSON")
	}
	actual, err := snap.computePayloadDigest()
	if err != nil {
		return nil, err
	}
	if actual != snap.PayloadSHA256 {
		return nil, newErr(403, ErrForbiddenQuery, "Pre-Mutation Snapshot SHA-256 verification failed (possible file tampering)")
	}
	if strings.TrimSpace(expectedSHA256) != "" && strings.TrimSpace(expectedSHA256) != actual {
		return nil, newErr(403, ErrForbiddenQuery, "Pre-Mutation Snapshot digest mismatch against ledger record")
	}
	return &snap, nil
}

func decodeTypedCellArg(cell TypedCell) (any, error) {
	switch cell.Kind {
	case "null":
		return nil, nil
	case "int":
		n, err := strconv.ParseInt(cell.Value, 10, 64)
		if err != nil {
			return cell.Value, nil
		}
		return n, nil
	case "real":
		f, err := strconv.ParseFloat(cell.Value, 64)
		if err != nil {
			return cell.Value, nil
		}
		return f, nil
	case "blob":
		return base64.StdEncoding.DecodeString(cell.Value)
	default:
		return cell.Value, nil
	}
}

func applyTableSnapshotRestore(ctx context.Context, db *sql.DB, engine string, snap *TableSnapshot) (int, error) {
	if strings.TrimSpace(snap.TableName) == "" {
		return 0, newErr(422, ErrValidation, "snapshot has no associated table name to restore")
	}
	quotedTable, err := QuoteIdent(engine, snap.TableName)
	if err != nil {
		return 0, err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if !snap.ExistedBefore {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", quotedTable)); err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return 0, nil
	}

	if snap.CreateSQL != "" {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", quotedTable)); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, snap.CreateSQL); err != nil {
			return 0, err
		}
	} else {
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", quotedTable)); err != nil {
			return 0, err
		}
	}

	if len(snap.Columns) > 0 && len(snap.Rows) > 0 {
		quotedCols := make([]string, len(snap.Columns))
		placeholders := make([]string, len(snap.Columns))
		for i, col := range snap.Columns {
			qCol, qErr := QuoteIdent(engine, col)
			if qErr != nil {
				return 0, qErr
			}
			quotedCols[i] = qCol
			if engine == "postgres" {
				placeholders[i] = fmt.Sprintf("$%d", i+1)
			} else {
				placeholders[i] = "?"
			}
		}
		insertSQL := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			quotedTable,
			strings.Join(quotedCols, ", "),
			strings.Join(placeholders, ", "),
		)
		stmt, err := tx.PrepareContext(ctx, insertSQL)
		if err != nil {
			return 0, err
		}
		defer stmt.Close()

		for _, row := range snap.Rows {
			args := make([]any, len(row))
			for i, c := range row {
				val, decErr := decodeTypedCellArg(c)
				if decErr != nil {
					return 0, decErr
				}
				args[i] = val
			}
			if _, err := stmt.ExecContext(ctx, args...); err != nil {
				return 0, err
			}
		}
	}

	for _, idxSQL := range snap.IndexSQLs {
		if _, err := tx.ExecContext(ctx, idxSQL); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(snap.Rows), nil
}
