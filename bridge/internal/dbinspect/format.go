package dbinspect

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ColumnMeta describes one result-set column in browser-friendly form.
type ColumnMeta struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key,omitempty"`
	DefaultVal string `json:"default_value,omitempty"`
}

// TypedCell preserves exact SQLite/Postgres/MariaDB storage fidelity for snapshots and wire formatting.
type TypedCell struct {
	Kind  string `json:"kind"` // null | int | real | text | blob
	Value string `json:"value"`
}

func isBinaryDBType(dbType string) bool {
	u := strings.ToUpper(dbType)
	return strings.Contains(u, "BLOB") || strings.Contains(u, "BINARY") || strings.Contains(u, "BYTEA")
}

func formatValue(raw any, dbType string) (wire any, cell TypedCell) {
	if raw == nil {
		return nil, TypedCell{Kind: "null", Value: ""}
	}
	switch v := raw.(type) {
	case int64:
		s := strconv.FormatInt(v, 10)
		return s, TypedCell{Kind: "int", Value: s}
	case int32:
		s := strconv.FormatInt(int64(v), 10)
		return s, TypedCell{Kind: "int", Value: s}
	case int:
		s := strconv.Itoa(v)
		return s, TypedCell{Kind: "int", Value: s}
	case uint64:
		s := strconv.FormatUint(v, 10)
		return s, TypedCell{Kind: "int", Value: s}
	case float64:
		s := strconv.FormatFloat(v, 'g', -1, 64)
		return s, TypedCell{Kind: "real", Value: s}
	case float32:
		s := strconv.FormatFloat(float64(v), 'g', -1, 32)
		return s, TypedCell{Kind: "real", Value: s}
	case bool:
		if v {
			return "true", TypedCell{Kind: "text", Value: "true"}
		}
		return "false", TypedCell{Kind: "text", Value: "false"}
	case time.Time:
		s := v.UTC().Format(time.RFC3339Nano)
		return s, TypedCell{Kind: "text", Value: s}
	case []byte:
		if isBinaryDBType(dbType) || !utf8.Valid(v) {
			return fmt.Sprintf("<BLOB %d bytes>", len(v)), TypedCell{Kind: "blob", Value: base64.StdEncoding.EncodeToString(v)}
		}
		s := string(v)
		return s, TypedCell{Kind: "text", Value: s}
	case string:
		return v, TypedCell{Kind: "text", Value: v}
	default:
		s := fmt.Sprintf("%v", v)
		return s, TypedCell{Kind: "text", Value: s}
	}
}

// ScanRows reads up to maxRows from sql.Rows, preserving ADR-025c exact base-10 wire strings
// for all numeric columns and bounding memory consumption.
func ScanRows(rows *sql.Rows, maxRows int) ([]ColumnMeta, []map[string]any, [][]TypedCell, bool, error) {
	colTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, nil, nil, false, err
	}
	colNames, err := rows.Columns()
	if err != nil {
		return nil, nil, nil, false, err
	}

	cols := make([]ColumnMeta, len(colNames))
	dbTypes := make([]string, len(colNames))
	for i, name := range colNames {
		dbType := ""
		nullable := true
		if i < len(colTypes) && colTypes[i] != nil {
			dbType = colTypes[i].DatabaseTypeName()
			if n, ok := colTypes[i].Nullable(); ok {
				nullable = n
			}
		}
		dbTypes[i] = dbType
		cols[i] = ColumnMeta{
			Name:     name,
			Type:     dbType,
			Nullable: nullable,
		}
	}

	records := make([]map[string]any, 0)
	typedRows := make([][]TypedCell, 0)
	truncated := false

	scanDest := make([]any, len(colNames))
	scanPtrs := make([]any, len(colNames))
	for i := range scanDest {
		scanPtrs[i] = &scanDest[i]
	}

	for rows.Next() {
		if maxRows > 0 && len(records) >= maxRows {
			truncated = true
			break
		}
		if err := rows.Scan(scanPtrs...); err != nil {
			return nil, nil, nil, false, err
		}
		rec := make(map[string]any, len(colNames))
		tRow := make([]TypedCell, len(colNames))
		for i, colName := range colNames {
			wire, cell := formatValue(scanDest[i], dbTypes[i])
			rec[colName] = wire
			tRow[i] = cell
		}
		records = append(records, rec)
		typedRows = append(typedRows, tRow)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, false, err
	}
	return cols, records, typedRows, truncated, nil
}
