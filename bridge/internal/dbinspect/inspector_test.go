package dbinspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gssh "gashboard/bridge/internal/ssh"
)

func setupTestSQLite(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dbPath := filepath.Join(root, "store.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("open test sqlite: %v", err)
	}
	defer db.Close()

	stmts := []string{
		`PRAGMA foreign_keys = ON;`,
		`CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE);`,
		`CREATE TABLE invoices (
			id INTEGER PRIMARY KEY,
			customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
			sku TEXT NOT NULL,
			amount_exact TEXT NOT NULL,
			qty INTEGER NOT NULL
		);`,
		`CREATE INDEX idx_invoices_sku ON invoices(sku);`,
		`INSERT INTO customers (id, email) VALUES (1, 'owner@urbans.press');`,
		`INSERT INTO invoices (id, customer_id, sku, amount_exact, qty) VALUES (9007199254740993, 1, 'SKU-ALPHA', '12345678901234567890.1234', 42);`,
		`INSERT INTO invoices (id, customer_id, sku, amount_exact, qty) VALUES (9007199254740995, 1, 'SKU-BETA', '99.9500', 7);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("exec setup %q: %v", s, err)
		}
	}
	return root, "store.db"
}

func TestResolveConfinedSQLiteBlocksTraversalAndSecrets(t *testing.T) {
	root, _ := setupTestSQLite(t)

	badPaths := []string{
		"",
		"../outside.db",
		`..\..\outside.db`,
		".env.db",
		".ssh/id_ed25519",
		".git/config.db",
		`\\server\share\test.db`,
		"/etc/passwd",
		`C:\Windows\system.db`,
		"notes.txt",
	}
	for _, p := range badPaths {
		_, err := ResolveConfinedSQLite(root, p)
		var ie *InspectorError
		if !errors.As(err, &ie) || ie.Code != ErrConfinement {
			t.Fatalf("expected %s for path %q, got err=%v", ErrConfinement, p, err)
		}
	}

	resolved, err := ResolveConfinedSQLite(root, "store.db")
	if err != nil {
		t.Fatalf("expected store.db to resolve cleanly: %v", err)
	}
	if !strings.HasSuffix(resolved, "store.db") {
		t.Fatalf("unexpected resolved path %q", resolved)
	}
}

func TestBrowseRowsADR025cAndPaginationLimits(t *testing.T) {
	root, dbName := setupTestSQLite(t)
	in := NewInspector(root, nil)
	ctx := context.Background()
	target := TargetSpec{TargetID: "sqlite:store", Engine: "sqlite", SQLitePath: dbName}

	schema, status, err := in.InspectSchema(ctx, target)
	if err != nil || status != 200 {
		t.Fatalf("InspectSchema failed (%d): %v", status, err)
	}
	if len(schema.Tables) != 2 {
		t.Fatalf("expected 2 tables, got %d", len(schema.Tables))
	}
	var invTbl TableSchema
	for _, tbl := range schema.Tables {
		if tbl.Name == "invoices" {
			invTbl = tbl
		}
	}
	if invTbl.RowCount != "2" || len(invTbl.ForeignKeys) != 1 || len(invTbl.Indexes) == 0 {
		t.Fatalf("unexpected invoices metadata: %+v", invTbl)
	}

	// Reject > 100 rows/page
	_, capStatus, capErr := in.BrowseRows(ctx, RowsRequest{
		Target: target,
		Table:  "invoices",
		Page:   "1",
		Limit:  "101",
	})
	if capErr == nil || capStatus != 422 {
		t.Fatalf("expected 422 for limit=101, got status=%d err=%v", capStatus, capErr)
	}

	// Reject SQL injection in table or filter column
	_, sqliStatus, sqliErr := in.BrowseRows(ctx, RowsRequest{
		Target: target,
		Table:  "invoices; DROP TABLE invoices",
		Page:   "1",
		Limit:  "10",
	})
	if sqliErr == nil || sqliStatus != 422 {
		t.Fatalf("expected 422 for invalid table ident, got %d %v", sqliStatus, sqliErr)
	}

	// Verify exact ADR-025c BIGINT (2^53+1) & DECIMAL preservation + safe parameterized filter
	rowsRes, st, err := in.BrowseRows(ctx, RowsRequest{
		Target:    target,
		Table:     "invoices",
		Page:      "1",
		Limit:     "25",
		SortCol:   "id",
		SortDir:   "ASC",
		FilterCol: "sku",
		FilterOp:  "eq",
		FilterVal: "SKU-ALPHA",
	})
	if err != nil || st != 200 {
		t.Fatalf("BrowseRows failed (%d): %v", st, err)
	}
	if rowsRes.TotalRows != "1" || len(rowsRes.Rows) != 1 {
		t.Fatalf("expected 1 filtered row, got %+v", rowsRes)
	}
	row0 := rowsRes.Rows[0]
	if gotID, _ := row0["id"].(string); gotID != "9007199254740993" {
		t.Fatalf("ADR-025c BIGINT drift: got %#v, want %q", row0["id"], "9007199254740993")
	}
	if gotAmt, _ := row0["amount_exact"].(string); gotAmt != "12345678901234567890.1234" {
		t.Fatalf("ADR-025c DECIMAL drift: got %#v", row0["amount_exact"])
	}
}

func TestReadOnlyQueryBlocksMutationsAndPrivilegedDirectives(t *testing.T) {
	root, dbName := setupTestSQLite(t)
	in := NewInspector(root, nil)
	ctx := context.Background()
	target := TargetSpec{TargetID: "sqlite:store", Engine: "sqlite", SQLitePath: dbName}

	blocked := []string{
		"DELETE FROM invoices WHERE id = 9007199254740993",
		"UPDATE invoices SET qty = 0",
		"INSERT INTO customers VALUES (2, 'bad@example.com')",
		"DROP TABLE invoices",
		"SELECT * FROM invoices; DELETE FROM invoices",
		"PRAGMA query_only = OFF",
		"ATTACH DATABASE '/tmp/x.db' AS x",
		"EXPLAIN DELETE FROM invoices",
	}
	for _, sqlText := range blocked {
		_, st, err := in.RunReadOnlyQuery(ctx, QueryRequest{Target: target, SQL: sqlText})
		var ie *InspectorError
		if !errors.As(err, &ie) || ie.Code != ErrForbiddenQuery || st != 403 {
			t.Fatalf("expected 403 %s for %q, got st=%d err=%v", ErrForbiddenQuery, sqlText, st, err)
		}
	}

	okRes, st, err := in.RunReadOnlyQuery(ctx, QueryRequest{
		Target: target,
		SQL:    "SELECT id, sku, amount_exact FROM invoices ORDER BY id ASC",
	})
	if err != nil || st != 200 || !okRes.ReadOnly || okRes.RowCount != "2" {
		t.Fatalf("read-only SELECT failed (%d): %+v err=%v", st, okRes, err)
	}
}

func TestMutationPlanExecuteExportAndSnapshotRestore(t *testing.T) {
	root, dbName := setupTestSQLite(t)
	in := NewInspector(root, nil)
	ctx := context.Background()
	target := TargetSpec{TargetID: "sqlite:store", Engine: "sqlite", SQLitePath: dbName}

	// 1. Export SQL first
	exp, st, err := in.ExportSQL(ctx, ExportRequest{Target: target, Table: "invoices", SaveFile: true, Filename: "invoices_bak.sql"})
	if err != nil || st != 200 || !strings.Contains(exp.SQLDump, "12345678901234567890.1234") || exp.ExportPath != "exports/invoices_bak.sql" {
		t.Fatalf("ExportSQL failed (%d): %+v err=%v", st, exp, err)
	}

	// 2. Plan DELETE mutation -> automatic Pre-Mutation Snapshot captured
	plan, st, err := in.PlanMutation(ctx, MutatePlanRequest{
		Target: target,
		SQL:    "DELETE FROM invoices WHERE sku = 'SKU-BETA'",
	})
	if err != nil || st != 200 || plan.TableName != "invoices" || plan.PreRowCount != "2" {
		t.Fatalf("PlanMutation failed (%d): %+v err=%v", st, plan, err)
	}

	// 3. Execute DELETE
	execRes, st, err := in.ExecuteMutation(ctx, MutateExecuteRequest{
		Target:     target,
		SQL:        "DELETE FROM invoices WHERE sku = 'SKU-BETA'",
		SnapshotID: plan.SnapshotID,
	})
	if err != nil || st != 200 || execRes.AffectedRows != "1" {
		t.Fatalf("ExecuteMutation failed (%d): %+v err=%v", st, execRes, err)
	}

	afterDel, _, err := in.BrowseRows(ctx, RowsRequest{Target: target, Table: "invoices", Page: "1", Limit: "25"})
	if err != nil || afterDel.TotalRows != "1" {
		t.Fatalf("expected 1 row after delete, got %+v err=%v", afterDel, err)
	}

	// 4. Reject tampered snapshot SHA-256
	_, tamperSt, tamperErr := in.RestoreSnapshot(ctx, RestoreRequest{
		Target:         target,
		SnapshotID:     plan.SnapshotID,
		ExpectedSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	if tamperErr == nil || tamperSt != 403 {
		t.Fatalf("expected 403 on snapshot digest mismatch, got st=%d err=%v", tamperSt, tamperErr)
	}

	// 5. Restore Pre-Mutation Snapshot -> original 2 rows + exact BIGINT/DECIMAL restored
	resRes, st, err := in.RestoreSnapshot(ctx, RestoreRequest{
		Target:         target,
		SnapshotID:     plan.SnapshotID,
		ExpectedSHA256: plan.BackupSHA256,
	})
	if err != nil || st != 200 || resRes.RestoredRows != "2" {
		t.Fatalf("RestoreSnapshot failed (%d): %+v err=%v", st, resRes, err)
	}

	afterRestore, _, err := in.BrowseRows(ctx, RowsRequest{Target: target, Table: "invoices", Page: "1", Limit: "25", SortCol: "id"})
	if err != nil || afterRestore.TotalRows != "2" {
		t.Fatalf("expected 2 rows after restore, got %+v err=%v", afterRestore, err)
	}
	if afterRestore.Rows[0]["amount_exact"] != "12345678901234567890.1234" {
		t.Fatalf("restored ADR-025c value mismatch: %+v", afterRestore.Rows[0])
	}

	// 6. Test DDL creation + rollback (table didn't exist before -> dropped cleanly)
	ddlSQL := "CREATE TABLE audit_temp (id INTEGER PRIMARY KEY, label TEXT)"
	ddlPlan, st, err := in.PlanMutation(ctx, MutatePlanRequest{Target: target, SQL: ddlSQL})
	if err != nil || st != 200 || ddlPlan.TableName != "audit_temp" {
		t.Fatalf("DDL PlanMutation failed: %+v err=%v", ddlPlan, err)
	}
	if _, st, err := in.ExecuteMutation(ctx, MutateExecuteRequest{Target: target, SQL: ddlSQL, SnapshotID: ddlPlan.SnapshotID}); err != nil || st != 200 {
		t.Fatalf("DDL ExecuteMutation failed: %v", err)
	}
	if _, _, err := in.RestoreSnapshot(ctx, RestoreRequest{Target: target, SnapshotID: ddlPlan.SnapshotID, ExpectedSHA256: ddlPlan.BackupSHA256}); err != nil {
		t.Fatalf("DDL RestoreSnapshot failed: %v", err)
	}
	finalSchema, _, _ := in.InspectSchema(ctx, target)
	for _, tbl := range finalSchema.Tables {
		if tbl.Name == "audit_temp" {
			t.Fatalf("expected audit_temp to be dropped after snapshot rollback")
		}
	}
	_ = os.Remove(filepath.Join(root, "exports", "invoices_bak.sql"))
}

// --- Fake Postgres v3 Wire Test Responder for Real Loopback Tunnel Transport Verification ---

func writePGMsg(w io.Writer, msgType byte, body []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = msgType
	binary.BigEndian.PutUint32(hdr[1:5], uint32(4+len(body)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func startFakePostgresServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake pg: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakePGConn(conn)
		}
	}()
	return ln.Addr().String()
}

func serveFakePGConn(c net.Conn) {
	defer c.Close()
	// Read StartupMessage (length + protocol 196608 or SSLRequest 80877103)
	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	sz := int(binary.BigEndian.Uint32(lenBuf[:]))
	if sz < 8 || sz > 8192 {
		return
	}
	payload := make([]byte, sz-4)
	if _, err := io.ReadFull(c, payload); err != nil {
		return
	}
	// If SSLRequest (80877103), respond 'N' and read actual StartupMessage
	if len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == 80877103 {
		_, _ = c.Write([]byte{'N'})
		if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
			return
		}
		sz = int(binary.BigEndian.Uint32(lenBuf[:]))
		if sz < 8 || sz > 8192 {
			return
		}
		payload = make([]byte, sz-4)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
	}

	// Send AuthenticationOk ('R', int32(0)), ParameterStatus, ReadyForQuery ('Z', 'I')
	var authZero [4]byte
	_ = writePGMsg(c, 'R', authZero[:])
	_ = writePGMsg(c, 'S', []byte("server_version\x0016.4\x00"))
	_ = writePGMsg(c, 'Z', []byte{'I'})

	inTxReadOnly := false
	lastQuery := ""
	binInt := false
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		mType := hdr[0]
		mLen := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
		if mLen < 0 || mLen > 1<<20 {
			return
		}
		body := make([]byte, mLen)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		txState := byte('I')
		if inTxReadOnly {
			txState = 'T'
		}
		switch mType {
		case 'X': // Terminate
			return
		case 'Q': // Simple query
			sqlStr := strings.TrimSuffix(string(body), "\x00")
			handlePGTextQuery(c, sqlStr, &inTxReadOnly)
		case 'P': // Parse (extended query used by pgx)
			parts := strings.SplitN(string(body), "\x00", 3)
			if len(parts) >= 2 {
				lastQuery = parts[1]
			}
			_ = writePGMsg(c, '1', nil) // ParseComplete
		case 'D': // Describe
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(lastQuery)), "SELECT") {
				_ = writePGMsg(c, 'T', encodePGCatalogRowDesc())
			} else {
				_ = writePGMsg(c, 'n', nil) // NoData
			}
		case 'B': // Bind: detect requested result format codes at tail of Bind message
			binInt = len(body) >= 4 && binary.BigEndian.Uint16(body[len(body)-4:len(body)-2]) == 1
			_ = writePGMsg(c, '2', nil) // BindComplete
		case 'E': // Execute
			up := strings.ToUpper(strings.TrimSpace(lastQuery))
			if strings.HasPrefix(up, "BEGIN") {
				inTxReadOnly = true
				_ = writePGMsg(c, 'C', []byte("BEGIN\x00"))
			} else if strings.HasPrefix(up, "ROLLBACK") {
				inTxReadOnly = false
				_ = writePGMsg(c, 'C', []byte("ROLLBACK\x00"))
			} else if strings.HasPrefix(up, "SELECT") {
				_ = writePGMsg(c, 'D', encodePGCatalogDataRow(binInt))
				_ = writePGMsg(c, 'C', []byte("SELECT 1\x00"))
			} else {
				_ = writePGMsg(c, 'C', []byte("OK\x00"))
			}
		case 'S': // Sync
			_ = writePGMsg(c, 'Z', []byte{txState})
		}
	}
}

func handlePGTextQuery(c net.Conn, sqlStr string, inTx *bool) {
	up := strings.ToUpper(strings.TrimSpace(sqlStr))
	if strings.Contains(up, "BEGIN") {
		*inTx = true
		_ = writePGMsg(c, 'C', []byte("BEGIN\x00"))
	} else if strings.Contains(up, "ROLLBACK") {
		*inTx = false
		_ = writePGMsg(c, 'C', []byte("ROLLBACK\x00"))
	} else if strings.HasPrefix(up, "SELECT") {
		_ = writePGMsg(c, 'T', encodePGCatalogRowDesc())
		_ = writePGMsg(c, 'D', encodePGRow([]string{"9007199254740993", "12345678901234567890.1234"}))
		_ = writePGMsg(c, 'C', []byte("SELECT 1\x00"))
	} else {
		_ = writePGMsg(c, 'C', []byte("OK\x00"))
	}
	txState := byte('I')
	if *inTx {
		txState = 'T'
	}
	_ = writePGMsg(c, 'Z', []byte{txState})
}

func encodePGCatalogRowDesc() []byte {
	// 2 columns: id (OID 20 int8 -> 8 bytes), price (OID 1700 numeric -> -1 var)
	cols := []struct {
		name string
		oid  uint32
		size int16
	}{
		{"id", 20, 8},
		{"price", 1700, -1},
	}
	var out []byte
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], 2)
	out = append(out, cnt[:]...)
	for _, col := range cols {
		out = append(out, col.name...)
		out = append(out, 0)
		var meta [18]byte
		binary.BigEndian.PutUint32(meta[6:10], col.oid)
		binary.BigEndian.PutUint16(meta[10:12], uint16(col.size))
		binary.BigEndian.PutUint32(meta[12:16], 0xffffffff)
		out = append(out, meta[:]...)
	}
	return out
}

func encodePGCatalogDataRow(binInt bool) []byte {
	var out []byte
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], 2)
	out = append(out, cnt[:]...)

	if binInt {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], 8)
		out = append(out, l[:]...)
		var num [8]byte
		binary.BigEndian.PutUint64(num[:], 9007199254740993)
		out = append(out, num[:]...)
	} else {
		v0 := "9007199254740993"
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(v0)))
		out = append(out, l[:]...)
		out = append(out, v0...)
	}

	v1 := "12345678901234567890.1234"
	var l1 [4]byte
	binary.BigEndian.PutUint32(l1[:], uint32(len(v1)))
	out = append(out, l1[:]...)
	out = append(out, v1...)
	return out
}

func encodePGRow(vals []string) []byte {
	var out []byte
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(vals)))
	out = append(out, cnt[:]...)
	for _, v := range vals {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(v)))
		out = append(out, l[:]...)
		out = append(out, v...)
	}
	return out
}

func TestTunneledPostgresRequiresActiveTunnelAndPreservesADR025c(t *testing.T) {
	pgAddr := startFakePostgresServer(t)

	// Reject direct host or missing tunnel
	inNoTun := NewInspector(t.TempDir(), gssh.NewTunnelManager(nil))
	_, st, err := inNoTun.RunReadOnlyQuery(context.Background(), QueryRequest{
		Target: TargetSpec{Engine: "postgres", DirectHost: "203.0.113.5", DBName: "app"},
		SQL:    "SELECT 1",
	})
	if err == nil || st != 422 {
		t.Fatalf("expected 422 rejecting direct host, got %d %v", st, err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	sum := sha256.Sum256(der)
	fp := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	khLine := "[127.0.0.1]:2222 ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(der)

	kh, err := gssh.NewKnownHostsVerifier([]string{khLine})
	if err != nil {
		t.Fatalf("KnownHostsVerifier: %v", err)
	}
	tm := gssh.NewTunnelManager(kh)
	defer tm.CloseAll()

	tunRec, err := tm.OpenTunnel(context.Background(), gssh.TunnelConfig{
		NodeID:             "vps_pg_1",
		SSHHost:            "127.0.0.1",
		SSHPort:            2222,
		HostKeyFingerprint: fp,
		Engine:             "postgres",
		RemoteTargetAddr:   pgAddr,
		TTLMinutes:         10,
	})
	if err != nil {
		t.Fatalf("OpenTunnel: %v", err)
	}

	in := NewInspector(t.TempDir(), tm)
	res, qSt, qErr := in.RunReadOnlyQuery(context.Background(), QueryRequest{
		Target: TargetSpec{
			TargetID: "tun:" + tunRec.ID,
			Engine:   "postgres",
			TunnelID: tunRec.ID,
			DBUser:   "deploy",
			DBName:   "store",
		},
		SQL: "SELECT id, price FROM catalog",
	})
	if qErr != nil || qSt != 200 {
		t.Fatalf("tunneled PG query failed (%d): %v", qSt, qErr)
	}
	if len(res.Rows) != 1 || res.Rows[0]["id"] != "9007199254740993" || res.Rows[0]["price"] != "12345678901234567890.1234" {
		t.Fatalf("unexpected tunneled PG result: %+v", res.Rows)
	}
}
