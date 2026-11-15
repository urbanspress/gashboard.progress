package dbinspect

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// ErrConfinement matches GRAB's workspace-confinement error code for unsafe DB file paths.
	ErrConfinement = "GRAB-E401"
	// ErrForbiddenQuery rejects unapproved DML/DDL or dangerous SQL commands.
	ErrForbiddenQuery = "GASH-E403"
	// ErrValidation rejects invalid pagination bounds, non-loopback targets, or malformed numbers.
	ErrValidation = "GASH-E422"

	// MaxRowsPerPage enforces ADR/GASHBOARD-SPEC-002 bounded pagination (<= 100).
	MaxRowsPerPage = 100
)

// InspectorError carries structured Gashboard/GRAB error codes across the bridge API.
type InspectorError struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *InspectorError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newErr(status int, code, msg string) *InspectorError {
	return &InspectorError{HTTPStatus: status, Code: code, Message: msg}
}

var identRegex = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// ValidateIdentifier restricts SQL database/schema/table/column identifiers to safe ASCII characters.
func ValidateIdentifier(name string) error {
	clean := strings.TrimSpace(name)
	if !identRegex.MatchString(clean) {
		return newErr(422, ErrValidation, fmt.Sprintf("invalid SQL identifier %q: expected ^[A-Za-z_][A-Za-z0-9_]{0,63}$", name))
	}
	return nil
}

// QuoteIdent validates and safely quotes a SQL identifier using engine-specific delimiters.
func QuoteIdent(engine, name string) (string, error) {
	if err := ValidateIdentifier(name); err != nil {
		return "", err
	}
	clean := strings.TrimSpace(name)
	switch NormalizeEngine(engine) {
	case "mariadb":
		return "`" + clean + "`", nil
	default:
		return `"` + clean + `"`, nil
	}
}

// NormalizeEngine canonicalizes supported database engine names.
func NormalizeEngine(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "sqlite", "sqlite3":
		return "sqlite"
	case "postgres", "postgresql":
		return "postgres"
	case "mariadb", "mysql":
		return "mariadb"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

var sensitiveSegments = map[string]bool{
	".git":            true,
	".ssh":            true,
	".gnupg":          true,
	"id_rsa":          true,
	"id_ed25519":      true,
	"known_hosts":     true,
	"authorized_keys": true,
	"secrets":         true,
}

func hasSensitiveSegment(relSlash string) bool {
	for _, seg := range strings.Split(relSlash, "/") {
		low := strings.ToLower(strings.TrimSpace(seg))
		if low == "" || low == "." {
			continue
		}
		if low == ".." || sensitiveSegments[low] || strings.HasPrefix(low, ".env") {
			return true
		}
	}
	return false
}

// ResolveConfinedSQLite validates and resolves a SQLite database file strictly inside sqliteRoot.
// Any traversal, UNC path, sensitive file segment, symlink escape, or non-SQLite extension returns GRAB-E401.
func ResolveConfinedSQLite(sqliteRoot, rawPath string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" || strings.ContainsRune(trimmed, '\x00') {
		return "", newErr(403, ErrConfinement, "SQLite path is empty or contains invalid NUL bytes")
	}
	if strings.HasPrefix(trimmed, `\\`) || strings.HasPrefix(trimmed, `//`) {
		return "", newErr(403, ErrConfinement, "UNC/network SQLite paths are blocked")
	}
	slashPath := strings.ReplaceAll(trimmed, `\`, `/`)
	if hasSensitiveSegment(slashPath) {
		return "", newErr(403, ErrConfinement, "traversal or sensitive path segment blocked")
	}
	if strings.HasPrefix(trimmed, `/`) || strings.HasPrefix(trimmed, `\`) || filepath.IsAbs(trimmed) || filepath.VolumeName(trimmed) != "" {
		return "", newErr(403, ErrConfinement, "absolute SQLite paths outside configured workspace root are blocked")
	}

	rootClean := strings.TrimSpace(sqliteRoot)
	if rootClean == "" {
		rootClean = "storage"
	}
	absRoot, err := filepath.Abs(rootClean)
	if err != nil {
		return "", newErr(403, ErrConfinement, "invalid configured SQLite root")
	}
	if evalRoot, evalErr := filepath.EvalSymlinks(absRoot); evalErr == nil {
		absRoot = evalRoot
	}

	normRel := strings.TrimPrefix(slashPath, "./")
	if strings.EqualFold(filepath.Base(absRoot), "storage") && strings.HasPrefix(strings.ToLower(normRel), "storage/") {
		normRel = normRel[len("storage/"):]
	}
	if normRel == "" || normRel == "." || hasSensitiveSegment(normRel) {
		return "", newErr(403, ErrConfinement, "SQLite path resolves to directory or unsafe segment")
	}

	candidate := filepath.Join(absRoot, filepath.FromSlash(normRel))
	absCand, err := filepath.Abs(candidate)
	if err != nil {
		return "", newErr(403, ErrConfinement, "could not resolve SQLite path")
	}
	if !isWithinDir(absRoot, absCand) {
		return "", newErr(403, ErrConfinement, "SQLite path escapes configured storage root")
	}

	ext := strings.ToLower(filepath.Ext(absCand))
	if ext != ".db" && ext != ".sqlite" && ext != ".sqlite3" {
		return "", newErr(403, ErrConfinement, "only .db, .sqlite, or .sqlite3 files are permitted for inspection")
	}

	// Verify symlink safety on parent directory and file (if it exists).
	parentDir := filepath.Dir(absCand)
	if evalParent, pErr := filepath.EvalSymlinks(parentDir); pErr == nil {
		if !isWithinDir(absRoot, evalParent) && !samePath(absRoot, evalParent) {
			return "", newErr(403, ErrConfinement, "symlink parent directory escapes SQLite root")
		}
	}
	info, statErr := os.Lstat(absCand)
	if statErr == nil {
		if info.IsDir() {
			return "", newErr(403, ErrConfinement, "SQLite target cannot be a directory")
		}
		if evalFile, fErr := filepath.EvalSymlinks(absCand); fErr == nil {
			if !isWithinDir(absRoot, evalFile) {
				return "", newErr(403, ErrConfinement, "SQLite symlink target escapes storage root")
			}
			absCand = evalFile
		}
	}
	return absCand, nil
}

func isWithinDir(rootDir, target string) bool {
	rel, err := filepath.Rel(rootDir, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func samePath(a, b string) bool {
	rel, err := filepath.Rel(a, b)
	return err == nil && rel == "."
}

// ValidatePageLimit parses base-10 wire strings page and limit, enforcing 1 <= limit <= 100.
func ValidatePageLimit(pageRaw, limitRaw string) (int, int, error) {
	pStr := strings.TrimSpace(pageRaw)
	if pStr == "" {
		pStr = "1"
	}
	lStr := strings.TrimSpace(limitRaw)
	if lStr == "" {
		lStr = "25"
	}
	if !IsExactDecimalWire(pStr) || !IsExactDecimalWire(lStr) {
		return 0, 0, newErr(422, ErrValidation, "page and limit must be exact base-10 integer strings (ADR-025c)")
	}
	page, err := strconv.Atoi(pStr)
	if err != nil || page < 1 {
		return 0, 0, newErr(422, ErrValidation, "page must be >= 1")
	}
	limit, err := strconv.Atoi(lStr)
	if err != nil || limit < 1 || limit > MaxRowsPerPage {
		return 0, 0, newErr(422, ErrValidation, fmt.Sprintf("limit must be between 1 and %d rows per page", MaxRowsPerPage))
	}
	return page, limit, nil
}

// IsExactDecimalWire checks base-10 numeric wire formatting without IEEE-754 rounding artifacts.
func IsExactDecimalWire(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if strings.Contains(s, "000000") || strings.Contains(s, "999999") {
		return false
	}
	if strings.HasPrefix(s, "-") {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	dots := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '.' {
			dots++
			if dots > 1 || i == 0 || i == len(s)-1 {
				return false
			}
			continue
		}
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// StatementKind categorizes SQL statements for GROXY-SAFE-001 safety gates.
type StatementKind string

const (
	KindReadOnly StatementKind = "read_only"
	KindDML      StatementKind = "dml"
	KindDDL      StatementKind = "ddl"
	KindImport   StatementKind = "import"
)

// ClassifiedSQL captures statement classification and primary affected table name.
type ClassifiedSQL struct {
	Kind        StatementKind
	Verb        string
	Statements  []string
	TableName   string
	Summary     string
	IsDangerous bool
	DangerNote  string
}

var blockedSQLKeywords = []string{
	"ATTACH DATABASE",
	"LOAD_EXTENSION",
	"INTO OUTFILE",
	"INTO DUMPFILE",
	"LOAD DATA",
	"COPY ",
	"WRITABLE_SCHEMA",
	"QUERY_ONLY",
}

// ClassifySQL inspects SQL text cleanly using quote/comment-aware statement splitting.
func ClassifySQL(rawSQL string) (ClassifiedSQL, error) {
	stmts, err := splitSQLStatements(rawSQL)
	if err != nil {
		return ClassifiedSQL{}, err
	}
	if len(stmts) == 0 {
		return ClassifiedSQL{}, newErr(422, ErrValidation, "SQL statement cannot be empty")
	}

	for _, st := range stmts {
		upperNoStrings := stripQuotedStringsUpper(st)
		for _, bad := range blockedSQLKeywords {
			if strings.Contains(upperNoStrings, bad) {
				if bad == "COPY " && !strings.Contains(upperNoStrings, "FROM PROGRAM") && !strings.Contains(upperNoStrings, "TO ") {
					continue
				}
				return ClassifiedSQL{IsDangerous: true, DangerNote: bad}, newErr(403, ErrForbiddenQuery, fmt.Sprintf("SQL contains disallowed privileged directive (%s)", strings.TrimSpace(bad)))
			}
		}
	}

	if len(stmts) > 1 {
		firstTable := ""
		for _, st := range stmts {
			if t := extractTableFromSQL(st); t != "" {
				firstTable = t
				break
			}
		}
		return ClassifiedSQL{
			Kind:       KindImport,
			Verb:       "IMPORT",
			Statements: stmts,
			TableName:  firstTable,
			Summary:    fmt.Sprintf("Multi-statement SQL import (%d statements)", len(stmts)),
		}, nil
	}

	single := stmts[0]
	verb := firstKeyword(single)
	tableName := extractTableFromSQL(single)

	switch verb {
	case "SELECT", "SHOW", "DESCRIBE", "DESC":
		if hasMutatingKeywordOutsideQuotes(single) {
			return ClassifiedSQL{}, newErr(403, ErrForbiddenQuery, "read-only query cannot include nested DML/DDL keywords")
		}
		return ClassifiedSQL{
			Kind:       KindReadOnly,
			Verb:       verb,
			Statements: stmts,
			TableName:  tableName,
			Summary:    fmt.Sprintf("Read-only %s query", verb),
		}, nil
	case "WITH":
		if hasMutatingKeywordOutsideQuotes(single) {
			return ClassifiedSQL{
				Kind:       KindDML,
				Verb:       "WITH_MUTATE",
				Statements: stmts,
				TableName:  tableName,
				Summary:    "Mutating CTE query (requires human approval + Pre-Mutation Snapshot)",
			}, nil
		}
		return ClassifiedSQL{
			Kind:       KindReadOnly,
			Verb:       "SELECT",
			Statements: stmts,
			TableName:  tableName,
			Summary:    "Read-only CTE SELECT query",
		}, nil
	case "EXPLAIN":
		if hasMutatingKeywordOutsideQuotes(single) {
			return ClassifiedSQL{}, newErr(403, ErrForbiddenQuery, "EXPLAIN on mutating statements is blocked in read-only mode; use Mutate Plan instead")
		}
		return ClassifiedSQL{
			Kind:       KindReadOnly,
			Verb:       "EXPLAIN",
			Statements: stmts,
			TableName:  tableName,
			Summary:    "Read-only EXPLAIN plan",
		}, nil
	case "PRAGMA":
		upper := stripQuotedStringsUpper(single)
		if strings.Contains(upper, "=") {
			return ClassifiedSQL{}, newErr(403, ErrForbiddenQuery, "mutating PRAGMA assignment is blocked")
		}
		return ClassifiedSQL{
			Kind:       KindReadOnly,
			Verb:       "PRAGMA",
			Statements: stmts,
			TableName:  tableName,
			Summary:    "Read-only PRAGMA inspection",
		}, nil
	case "INSERT", "UPDATE", "DELETE", "REPLACE":
		return ClassifiedSQL{
			Kind:       KindDML,
			Verb:       verb,
			Statements: stmts,
			TableName:  tableName,
			Summary:    fmt.Sprintf("Row mutation (%s on %s)", verb, fallbackLabel(tableName)),
		}, nil
	case "CREATE", "ALTER", "DROP", "TRUNCATE":
		return ClassifiedSQL{
			Kind:       KindDDL,
			Verb:       verb,
			Statements: stmts,
			TableName:  tableName,
			Summary:    fmt.Sprintf("Schema change (%s on %s)", verb, fallbackLabel(tableName)),
		}, nil
	default:
		return ClassifiedSQL{}, newErr(403, ErrForbiddenQuery, fmt.Sprintf("unsupported or restricted SQL statement verb %q", verb))
	}
}

func fallbackLabel(name string) string {
	if strings.TrimSpace(name) == "" {
		return "target table"
	}
	return name
}

func splitSQLStatements(sqlText string) ([]string, error) {
	var stmts []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	inBacktick := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		next := byte(0)
		if i+1 < len(sqlText) {
			next = sqlText[i+1]
		}

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				cur.WriteByte(' ')
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && next == '/' {
				inBlockComment = false
				i++
				cur.WriteByte(' ')
			}
			continue
		}
		if !inSingle && !inDouble && !inBacktick {
			if ch == '-' && next == '-' {
				inLineComment = true
				i++
				continue
			}
			if ch == '/' && next == '*' {
				inBlockComment = true
				i++
				continue
			}
			if ch == ';' {
				s := strings.TrimSpace(cur.String())
				if s != "" {
					stmts = append(stmts, s)
				}
				cur.Reset()
				continue
			}
		}

		if ch == '\'' && !inDouble && !inBacktick {
			if inSingle && next == '\'' {
				cur.WriteByte(ch)
				cur.WriteByte(next)
				i++
				continue
			}
			inSingle = !inSingle
		} else if ch == '"' && !inSingle && !inBacktick {
			if inDouble && next == '"' {
				cur.WriteByte(ch)
				cur.WriteByte(next)
				i++
				continue
			}
			inDouble = !inDouble
		} else if ch == '`' && !inSingle && !inDouble {
			inBacktick = !inBacktick
		}

		cur.WriteByte(ch)
	}
	if inSingle || inDouble || inBacktick || inBlockComment {
		return nil, newErr(422, ErrValidation, "unterminated string literal, identifier quote, or comment in SQL")
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts, nil
}

func stripQuotedStringsUpper(sqlText string) string {
	var b strings.Builder
	inSingle := false
	inDouble := false
	inBacktick := false
	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		if ch == '\'' && !inDouble && !inBacktick {
			inSingle = !inSingle
			b.WriteByte(' ')
			continue
		}
		if ch == '"' && !inSingle && !inBacktick {
			inDouble = !inDouble
			b.WriteByte(' ')
			continue
		}
		if ch == '`' && !inSingle && !inDouble {
			inBacktick = !inBacktick
			b.WriteByte(' ')
			continue
		}
		if inSingle || inDouble || inBacktick {
			b.WriteByte(' ')
			continue
		}
		if ch >= 'a' && ch <= 'z' {
			ch = ch - 'a' + 'A'
		}
		b.WriteByte(ch)
	}
	return b.String()
}

var tokenRegex = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func firstKeyword(stmt string) string {
	cleaned := stripQuotedStringsUpper(stmt)
	m := tokenRegex.FindString(cleaned)
	return strings.ToUpper(m)
}

func hasMutatingKeywordOutsideQuotes(stmt string) bool {
	upper := stripQuotedStringsUpper(stmt)
	tokens := tokenRegex.FindAllString(upper, -1)
	for _, tok := range tokens {
		switch tok {
		case "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP", "TRUNCATE", "GRANT", "REVOKE", "VACUUM":
			return true
		}
	}
	return false
}

var tablePatternList = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^\s*INSERT\s+(?:OR\s+\w+\s+|IGNORE\s+)?INTO\s+[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
	regexp.MustCompile(`(?i)^\s*REPLACE\s+INTO\s+[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
	regexp.MustCompile(`(?i)^\s*UPDATE\s+[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
	regexp.MustCompile(`(?i)^\s*DELETE\s+FROM\s+[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
	regexp.MustCompile(`(?i)^\s*(?:CREATE|ALTER|DROP|TRUNCATE)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
	regexp.MustCompile(`(?i)\bFROM\s+[` + "`\"" + `]?([A-Za-z_][A-Za-z0-9_]*)[` + "`\"" + `]?`),
}

func extractTableFromSQL(stmt string) string {
	for _, re := range tablePatternList {
		if m := re.FindStringSubmatch(stmt); len(m) >= 2 {
			if err := ValidateIdentifier(m[1]); err == nil {
				return m[1]
			}
		}
	}
	return ""
}
