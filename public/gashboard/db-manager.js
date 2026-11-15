/**
 * Gashboard v0.2.0 — Pure Grex JS v1.0.0 Built-In phpMyAdmin-Style Visual Database Manager.
 * Transport: active 127.0.0.1 SSH tunnels (PostgreSQL, MariaDB) or confined local SQLite.
 * Safety: read-only default queries, <= 100 row cap, ADR-025c base-10 wire strings,
 *         GROXY-SAFE-001 Pre-Mutation Snapshot + X-CSRF-Token + single-use approval_token.
 * DOM Invariant: zero wrapper <div> elements, zero innerHTML writes, 100% WCAG AA.
 */

import { setSafeText, signal } from "./grex.js";
import { assertExactWireNumbers, isValidPaginationStrings } from "./api-client.js";

function el(doc, tag, attrs = {}, text = "") {
  const node = doc.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && v !== null) {
      node.setAttribute(k, String(v));
    }
  }
  if (text !== "") {
    setSafeText(node, text);
  }
  return node;
}

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

export function createDbManagerPanel({ doc, api }) {
  const targetsSig = signal([
    {
      target_id: "sqlite:gashboard.db",
      label: "Confined Workspace SQLite (gashboard.db)",
      engine: "sqlite",
      sqlite_path: "gashboard.db",
      transport: "local-confined",
    },
  ]);
  const schemaSig = signal({ ok: false, tables: [], databases: [] });
  const selectedTableSig = signal("");
  const rowsSig = signal({ columns: [], rows: [], page: "1", limit: "25", total_rows: "0", total_pages: "1" });
  const querySig = signal(null);
  const planSig = signal(null);
  const exportSig = signal(null);
  const snapshotsSig = signal([]);
  const statusSig = signal("");
  const errSig = signal("");

  const section = el(doc, "section", {
    id: "gashboard-db-manager",
    class: "gash-card",
    "aria-label": "Built-In Visual Database Manager (127.0.0.1 Tunnel & Confined SQLite)",
  });

  const heading = el(doc, "h2", {}, "Built-In Visual Database Manager");
  const intro = el(
    doc,
    "p",
    { class: "gash-muted" },
    "Inspect schemas, browse <= 100 rows per page with exact ADR-025c numeric fidelity, run read-only SELECT/EXPLAIN queries by default, and protect every write/DDL change with an automatic Pre-Mutation Snapshot and 1-click rollback—zero public database admin ports."
  );
  section.appendChild(heading);
  section.appendChild(intro);

  // Target Connection Form
  const targetGrid = el(doc, "fieldset", { class: "gash-grid-4" });
  const legend = el(doc, "legend", {}, "1. Select Private Database Target (SSH Tunnel or Confined SQLite)");
  targetGrid.appendChild(legend);

  const fTarget = el(doc, "p", { class: "gash-field" });
  fTarget.appendChild(el(doc, "label", { for: "db-target-select" }, "Active Database Target"));
  const targetSelect = el(doc, "select", { id: "db-target-select", name: "target_id" });
  fTarget.appendChild(targetSelect);
  targetGrid.appendChild(fTarget);

  const fSqlitePath = el(doc, "p", { class: "gash-field" });
  fSqlitePath.appendChild(el(doc, "label", { for: "db-sqlite-path" }, "Confined SQLite Path (storage/)"));
  const sqliteInput = el(doc, "input", {
    id: "db-sqlite-path",
    name: "sqlite_path",
    type: "text",
    value: "gashboard.db",
    placeholder: "gashboard.db",
  });
  fSqlitePath.appendChild(sqliteInput);
  targetGrid.appendChild(fSqlitePath);

  const fDbUser = el(doc, "p", { class: "gash-field" });
  fDbUser.appendChild(el(doc, "label", { for: "db-user-input" }, "Tunnel DB User (Postgres/MariaDB)"));
  const dbUserInput = el(doc, "input", {
    id: "db-user-input",
    name: "db_user",
    type: "text",
    placeholder: "deploy",
    autocomplete: "off",
  });
  fDbUser.appendChild(dbUserInput);
  targetGrid.appendChild(fDbUser);

  const fDbName = el(doc, "p", { class: "gash-field" });
  fDbName.appendChild(el(doc, "label", { for: "db-name-input" }, "Tunnel Database Name"));
  const dbNameInput = el(doc, "input", {
    id: "db-name-input",
    name: "db_name",
    type: "text",
    placeholder: "store",
    autocomplete: "off",
  });
  fDbName.appendChild(dbNameInput);
  targetGrid.appendChild(fDbName);

  const fDbPass = el(doc, "p", { class: "gash-field" });
  fDbPass.appendChild(el(doc, "label", { for: "db-pass-input" }, "Session DB Password (Never Logged/Echoed)"));
  const dbPassInput = el(doc, "input", {
    id: "db-pass-input",
    name: "db_password",
    type: "password",
    autocomplete: "off",
  });
  fDbPass.appendChild(dbPassInput);
  targetGrid.appendChild(fDbPass);
  section.appendChild(targetGrid);

  const connActions = el(doc, "p", { class: "gash-actions" });
  const inspectBtn = el(doc, "button", { type: "button", id: "db-load-schema-btn", class: "gash-btn" }, "Inspect Schema");
  const refreshTargetsBtn = el(doc, "button", { type: "button", id: "db-refresh-targets-btn", class: "gash-btn gash-btn-secondary" }, "Refresh Targets");
  const exportBtn = el(doc, "button", { type: "button", id: "db-export-sql-btn", class: "gash-btn gash-btn-secondary" }, "Export Sanitized SQL");
  connActions.appendChild(inspectBtn);
  connActions.appendChild(refreshTargetsBtn);
  connActions.appendChild(exportBtn);
  section.appendChild(connActions);

  const alertBox = el(doc, "p", { class: "gash-muted", role: "status", "aria-live": "polite" }, "");
  section.appendChild(alertBox);

  const renderAlert = () => {
    const err = errSig.get();
    const okMsg = statusSig.get();
    if (err) {
      alertBox.setAttribute("class", "gash-alert-danger");
      alertBox.setAttribute("role", "alert");
      setSafeText(alertBox, err);
    } else if (okMsg) {
      alertBox.setAttribute("class", "gash-alert-pass");
      alertBox.setAttribute("role", "status");
      setSafeText(alertBox, okMsg);
    } else {
      alertBox.setAttribute("class", "gash-muted");
      alertBox.setAttribute("role", "status");
      setSafeText(alertBox, "");
    }
  };

  const currentTarget = () => {
    const selectedId = targetSelect.value || "sqlite:gashboard.db";
    const list = targetsSig.get();
    const match = list.find((item) => item.target_id === selectedId);
    if (!match || match.engine === "sqlite") {
      return {
        target_id: selectedId,
        engine: "sqlite",
        sqlite_path: (sqliteInput.value || "gashboard.db").trim(),
      };
    }
    return {
      target_id: match.target_id,
      engine: match.engine,
      tunnel_id: match.tunnel_id,
      db_user: (dbUserInput.value || "").trim(),
      db_password: dbPassInput.value || "",
      db_name: (dbNameInput.value || "").trim(),
    };
  };

  const renderTargets = () => {
    const prev = targetSelect.value;
    clearChildren(targetSelect);
    for (const t of targetsSig.get()) {
      targetSelect.appendChild(el(doc, "option", { value: t.target_id }, t.label));
    }
    if (prev && targetsSig.get().some((t) => t.target_id === prev)) {
      targetSelect.value = prev;
    }
  };

  // Main Semantic Workspace: Sidebar (Tables/Columns) + Right Pane (Rows)
  const workspace = el(doc, "section", { class: "gash-db-workspace", "aria-label": "Database Schema and Row Explorer" });
  const sidebar = el(doc, "aside", { class: "gash-db-sidebar", "aria-label": "Schema Explorer" });
  sidebar.appendChild(el(doc, "h3", {}, "Schema & Tables"));
  const schemaSummary = el(doc, "p", { class: "gash-muted" }, "Select Inspect Schema to list tables, columns, indexes, foreign keys, and exact row counts.");
  sidebar.appendChild(schemaSummary);
  const tableList = el(doc, "ul", { class: "gash-db-table-list" });
  sidebar.appendChild(tableList);
  const tableStructDetails = el(doc, "details", { open: "open" });
  tableStructDetails.appendChild(el(doc, "summary", {}, "Columns, Indexes & Foreign Keys"));
  const structTable = el(doc, "table", { class: "gash-table" });
  tableStructDetails.appendChild(structTable);
  sidebar.appendChild(tableStructDetails);
  workspace.appendChild(sidebar);

  const mainPane = el(doc, "section", { class: "gash-db-main", "aria-label": "Paginated Table Row Browser" });
  mainPane.appendChild(el(doc, "h3", {}, "Paginated Row Browser (<= 100 / Page)"));

  const filterBar = el(doc, "form", { class: "gash-grid-4", "aria-label": "Filter Sort and Pagination Controls" });
  const fTable = el(doc, "p", { class: "gash-field" });
  fTable.appendChild(el(doc, "label", { for: "db-browse-table" }, "Table"));
  const tableInput = el(doc, "input", { id: "db-browse-table", name: "table", type: "text", placeholder: "vps_nodes" });
  fTable.appendChild(tableInput);
  filterBar.appendChild(fTable);

  const fFilterCol = el(doc, "p", { class: "gash-field" });
  fFilterCol.appendChild(el(doc, "label", { for: "db-filter-col" }, "Filter Column (Optional)"));
  const filterColInput = el(doc, "input", { id: "db-filter-col", name: "filter_col", type: "text", placeholder: "environment" });
  fFilterCol.appendChild(filterColInput);
  filterBar.appendChild(fFilterCol);

  const fFilterOp = el(doc, "p", { class: "gash-field" });
  fFilterOp.appendChild(el(doc, "label", { for: "db-filter-op" }, "Operator"));
  const filterOpSelect = el(doc, "select", { id: "db-filter-op", name: "filter_op" });
  for (const op of ["contains", "eq", "starts_with", "gt", "lt"]) {
    filterOpSelect.appendChild(el(doc, "option", { value: op }, op));
  }
  fFilterOp.appendChild(filterOpSelect);
  filterBar.appendChild(fFilterOp);

  const fFilterVal = el(doc, "p", { class: "gash-field" });
  fFilterVal.appendChild(el(doc, "label", { for: "db-filter-val" }, "Filter Value"));
  const filterValInput = el(doc, "input", { id: "db-filter-val", name: "filter_val", type: "text", placeholder: "production" });
  fFilterVal.appendChild(filterValInput);
  filterBar.appendChild(fFilterVal);

  const fSortCol = el(doc, "p", { class: "gash-field" });
  fSortCol.appendChild(el(doc, "label", { for: "db-sort-col" }, "Sort Column"));
  const sortColInput = el(doc, "input", { id: "db-sort-col", name: "sort_col", type: "text", placeholder: "id" });
  fSortCol.appendChild(sortColInput);
  filterBar.appendChild(fSortCol);

  const fSortDir = el(doc, "p", { class: "gash-field" });
  fSortDir.appendChild(el(doc, "label", { for: "db-sort-dir" }, "Direction"));
  const sortDirSelect = el(doc, "select", { id: "db-sort-dir", name: "sort_dir" });
  sortDirSelect.appendChild(el(doc, "option", { value: "ASC" }, "ASC"));
  sortDirSelect.appendChild(el(doc, "option", { value: "DESC" }, "DESC"));
  fSortDir.appendChild(sortDirSelect);
  filterBar.appendChild(fSortDir);

  const fPage = el(doc, "p", { class: "gash-field" });
  fPage.appendChild(el(doc, "label", { for: "db-page-input" }, "Page (Base-10 String)"));
  const pageInput = el(doc, "input", { id: "db-page-input", name: "page", type: "text", value: "1" });
  fPage.appendChild(pageInput);
  filterBar.appendChild(fPage);

  const fLimit = el(doc, "p", { class: "gash-field" });
  fLimit.appendChild(el(doc, "label", { for: "db-limit-input" }, "Rows/Page (<= 100)"));
  const limitInput = el(doc, "input", { id: "db-limit-input", name: "limit", type: "text", value: "25" });
  fLimit.appendChild(limitInput);
  filterBar.appendChild(fLimit);

  mainPane.appendChild(filterBar);

  const browseActions = el(doc, "p", { class: "gash-actions" });
  const browseBtn = el(doc, "button", { type: "button", id: "db-browse-rows-btn", class: "gash-btn" }, "Load Rows");
  const prevPageBtn = el(doc, "button", { type: "button", id: "db-prev-page-btn", class: "gash-btn gash-btn-secondary" }, "Previous Page");
  const nextPageBtn = el(doc, "button", { type: "button", id: "db-next-page-btn", class: "gash-btn gash-btn-secondary" }, "Next Page");
  const pageMeta = el(doc, "span", { class: "gash-muted" }, "Page 1 of 1 (0 rows)");
  browseActions.appendChild(browseBtn);
  browseActions.appendChild(prevPageBtn);
  browseActions.appendChild(nextPageBtn);
  browseActions.appendChild(pageMeta);
  mainPane.appendChild(browseActions);

  const rowTableWrap = el(doc, "section", { class: "gash-table-scroll", "aria-label": "Paginated Table Data" });
  const rowsTable = el(doc, "table", { class: "gash-table" });
  rowTableWrap.appendChild(rowsTable);
  mainPane.appendChild(rowTableWrap);

  workspace.appendChild(mainPane);
  section.appendChild(workspace);

  // Guarded Query & Mutation Section
  const sqlSection = el(doc, "section", { class: "gash-card", "aria-label": "Guarded SQL Query and Mutation Runner" });
  sqlSection.appendChild(el(doc, "h3", {}, "Guarded SQL Query & GROXY-SAFE-001 Mutation Runner"));
  const fSql = el(doc, "p", { class: "gash-field" });
  fSql.appendChild(el(doc, "label", { for: "db-sql-input" }, "SQL Statement (Read-Only Default; Writes Require Preview & Pre-Mutation Snapshot)"));
  const sqlInput = el(doc, "textarea", {
    id: "db-sql-input",
    class: "gash-sql-editor",
    name: "sql",
    rows: "4",
    placeholder: "SELECT id, label, host, cpu_pct, status FROM vps_nodes ORDER BY id ASC LIMIT 25;",
  });
  fSql.appendChild(sqlInput);
  sqlSection.appendChild(fSql);

  const sqlActions = el(doc, "p", { class: "gash-actions" });
  const runReadBtn = el(doc, "button", { type: "button", id: "db-run-query-btn", class: "gash-btn" }, "Run Read-Only Query");
  const planMutateBtn = el(doc, "button", { type: "button", id: "db-plan-mutate-btn", class: "gash-btn gash-btn-danger" }, "Preview Write/DDL & Capture Pre-Mutation Snapshot");
  sqlActions.appendChild(runReadBtn);
  sqlActions.appendChild(planMutateBtn);
  sqlSection.appendChild(sqlActions);

  const approvalCard = el(doc, "section", { id: "db-mutation-approval-card", "aria-label": "Pending Mutation Approval" });
  sqlSection.appendChild(approvalCard);

  const queryResultsWrap = el(doc, "section", { class: "gash-table-scroll", "aria-label": "SQL Query Results" });
  const queryResultsTable = el(doc, "table", { class: "gash-table" });
  queryResultsWrap.appendChild(queryResultsTable);
  sqlSection.appendChild(queryResultsWrap);

  const exportPre = el(doc, "pre", { class: "gash-code-line" }, "");
  sqlSection.appendChild(exportPre);
  section.appendChild(sqlSection);

  // Pre-Mutation Snapshots & 1-Click Rollback Ledger
  const snapSection = el(doc, "section", { class: "gash-card", "aria-label": "Pre-Mutation Snapshots and 1-Click Restore" });
  snapSection.appendChild(el(doc, "h3", {}, "Pre-Mutation Snapshots & 1-Click Rollback"));
  const snapTable = el(doc, "table", { class: "gash-table" });
  snapSection.appendChild(snapTable);
  section.appendChild(snapSection);

  const renderSchemaExplorer = () => {
    const sc = schemaSig.get();
    clearChildren(tableList);
    clearChildren(structTable);

    const tables = Array.isArray(sc.tables) ? sc.tables : [];
    setSafeText(
      schemaSummary,
      sc.ok
        ? `Connected (${sc.engine}: ${sc.target_label}) — ${tables.length} tables discovered.`
        : "Select Inspect Schema to load database metadata cleanly."
    );

    if (tables.length === 0) {
      return;
    }

    if (!selectedTableSig.get() || !tables.some((t) => t.name === selectedTableSig.get())) {
      selectedTableSig.set(tables[0].name);
      tableInput.value = tables[0].name;
    }

    const activeName = selectedTableSig.get();
    for (const tbl of tables) {
      const li = el(doc, "li");
      const btn = el(doc, "button", {
        type: "button",
        class: "gash-db-table-btn",
        "aria-current": tbl.name === activeName ? "true" : "false",
      });
      btn.appendChild(el(doc, "span", {}, tbl.name));
      btn.appendChild(el(doc, "span", { class: "gash-pill gash-pill-pass" }, `${tbl.row_count || "0"} rows`));
      btn.addEventListener("click", () => {
        selectedTableSig.set(tbl.name);
        tableInput.value = tbl.name;
        pageInput.value = "1";
        renderSchemaExplorer();
        browseRows().catch(() => {});
      });
      li.appendChild(btn);
      tableList.appendChild(li);
    }

    const activeTable = tables.find((t) => t.name === activeName) || tables[0];
    const thead = el(doc, "thead");
    const htr = el(doc, "tr");
    for (const h of ["Column", "Type", "Nullable", "Key/Notes"]) {
      htr.appendChild(el(doc, "th", {}, h));
    }
    thead.appendChild(htr);
    structTable.appendChild(thead);

    const tbody = el(doc, "tbody");
    for (const col of activeTable.columns || []) {
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", {}, col.name));
      tr.appendChild(el(doc, "td", {}, col.type || "TEXT"));
      tr.appendChild(el(doc, "td", {}, col.nullable ? "YES" : "NO"));
      tr.appendChild(el(doc, "td", {}, col.primary_key ? "PK" : col.default_value ? `default: ${col.default_value}` : "—"));
      tbody.appendChild(tr);
    }
    for (const idx of activeTable.indexes || []) {
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", {}, `INDEX: ${idx.name}`));
      tr.appendChild(el(doc, "td", {}, idx.unique ? "UNIQUE" : "INDEX"));
      tr.appendChild(el(doc, "td", {}, "—"));
      tr.appendChild(el(doc, "td", {}, (idx.columns || []).join(", ")));
      tbody.appendChild(tr);
    }
    for (const fk of activeTable.foreign_keys || []) {
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", {}, `FK: ${fk.column}`));
      tr.appendChild(el(doc, "td", {}, `-> ${fk.ref_table}(${fk.ref_column})`));
      tr.appendChild(el(doc, "td", {}, fk.on_delete || "NO ACTION"));
      tr.appendChild(el(doc, "td", {}, fk.on_update || "NO ACTION"));
      tbody.appendChild(tr);
    }
    structTable.appendChild(tbody);
  };

  const renderDataGrid = (tableEl, cols, rows, emptyLabel) => {
    clearChildren(tableEl);
    if (!Array.isArray(cols) || cols.length === 0) {
      const tb = el(doc, "tbody");
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", {}, emptyLabel));
      tb.appendChild(tr);
      tableEl.appendChild(tb);
      return;
    }
    const thead = el(doc, "thead");
    const htr = el(doc, "tr");
    for (const col of cols) {
      htr.appendChild(el(doc, "th", {}, col.name));
    }
    thead.appendChild(htr);
    tableEl.appendChild(thead);

    const tbody = el(doc, "tbody");
    if (!Array.isArray(rows) || rows.length === 0) {
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", { colspan: String(cols.length) }, emptyLabel));
      tbody.appendChild(tr);
    } else {
      for (const row of rows) {
        const tr = el(doc, "tr");
        for (const col of cols) {
          const val = row[col.name];
          tr.appendChild(el(doc, "td", {}, val === null || val === undefined ? "NULL" : String(val)));
        }
        tbody.appendChild(tr);
      }
    }
    tableEl.appendChild(tbody);
  };

  const renderRowsBrowser = () => {
    const data = rowsSig.get();
    setSafeText(
      pageMeta,
      `Page ${data.page || "1"} of ${data.total_pages || "1"} (${data.total_rows || "0"} total rows, limit ${data.limit || "25"})`
    );
    renderDataGrid(rowsTable, data.columns, data.rows, "Click Load Rows or pick a table to inspect rows.");
  };

  const renderQueryResults = () => {
    const q = querySig.get();
    if (!q) {
      renderDataGrid(queryResultsTable, [], [], "No read-only SQL query executed yet.");
      return;
    }
    renderDataGrid(queryResultsTable, q.columns || [], q.rows || [], `Query returned ${q.row_count || "0"} rows.`);
  };

  const renderApprovalCard = () => {
    clearChildren(approvalCard);
    const plan = planSig.get();
    if (!plan) {
      approvalCard.setAttribute("class", "");
      return;
    }
    approvalCard.setAttribute("class", "gash-approval-banner");
    approvalCard.appendChild(el(doc, "strong", {}, `Human Approval Required (GROXY-SAFE-001 · ${plan.verb || plan.kind})`));
    approvalCard.appendChild(el(doc, "p", {}, plan.plain_summary));
    approvalCard.appendChild(
      el(
        doc,
        "code",
        { class: "gash-code-line" },
        `Snapshot: ${plan.snapshot_id} · Pre-Mutation Rows: ${plan.pre_row_count} · SHA-256: ${plan.backup_sha256}`
      )
    );
    const actRow = el(doc, "p", { class: "gash-actions" });
    const execBtn = el(doc, "button", { type: "button", id: "db-execute-mutate-btn", class: "gash-btn gash-btn-danger" }, "Approve & Execute Mutation");
    const cancelBtn = el(doc, "button", { type: "button", id: "db-cancel-mutate-btn", class: "gash-btn gash-btn-secondary" }, "Cancel");
    execBtn.addEventListener("click", () => {
      executeMutation().catch(() => {});
    });
    cancelBtn.addEventListener("click", () => {
      planSig.set(null);
      renderApprovalCard();
    });
    actRow.appendChild(execBtn);
    actRow.appendChild(cancelBtn);
    approvalCard.appendChild(actRow);
  };

  const renderSnapshots = () => {
    clearChildren(snapTable);
    const thead = el(doc, "thead");
    const htr = el(doc, "tr");
    for (const h of ["Snapshot ID", "Target", "Table", "SHA-256", "Status", "Rollback Action"]) {
      htr.appendChild(el(doc, "th", {}, h));
    }
    thead.appendChild(htr);
    snapTable.appendChild(thead);

    const tbody = el(doc, "tbody");
    const snaps = snapshotsSig.get();
    if (snaps.length === 0) {
      const tr = el(doc, "tr");
      tr.appendChild(el(doc, "td", { colspan: "6" }, "No Pre-Mutation DB Snapshots recorded yet."));
      tbody.appendChild(tr);
    } else {
      for (const s of snaps) {
        const tr = el(doc, "tr");
        tr.appendChild(el(doc, "td", {}, s.id));
        tr.appendChild(el(doc, "td", {}, s.target_id));
        tr.appendChild(el(doc, "td", {}, s.table_name || "—"));
        tr.appendChild(el(doc, "td", {}, (s.backup_sha256 || "").slice(0, 20) + "..."));
        tr.appendChild(el(doc, "td", {}, s.status));
        const tdAct = el(doc, "td");
        if (s.restore_approval_token && s.status === "executed") {
          const rBtn = el(doc, "button", { type: "button", class: "gash-btn gash-btn-secondary" }, "1-Click Restore");
          rBtn.addEventListener("click", () => {
            restoreSnapshot(s.id, s.restore_approval_token).catch(() => {});
          });
          tdAct.appendChild(rBtn);
        } else {
          tdAct.appendChild(el(doc, "span", { class: "gash-muted" }, s.status === "restored" ? "Restored" : "Locked"));
        }
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
    }
    snapTable.appendChild(tbody);
  };

  const refreshTargets = async () => {
    try {
      const res = await api.get("/api/db/targets");
      if (Array.isArray(res.targets) && res.targets.length > 0) {
        targetsSig.set(res.targets);
        renderTargets();
      }
      return res;
    } catch (e) {
      errSig.set(e.message || "Failed to load DB targets");
      renderAlert();
      return null;
    }
  };

  const loadSchema = async () => {
    errSig.set("");
    statusSig.set("");
    try {
      const target = currentTarget();
      const res = await api.post("/api/db/schema", { target });
      schemaSig.set(res);
      renderSchemaExplorer();
      statusSig.set(`Loaded schema for ${res.target_label || target.target_id}.`);
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Schema inspection failed");
      renderAlert();
      return null;
    }
  };

  const browseRows = async () => {
    errSig.set("");
    statusSig.set("");
    const table = (tableInput.value || selectedTableSig.get() || "").trim();
    const page = (pageInput.value || "1").trim();
    const limit = (limitInput.value || "25").trim();
    if (!table) {
      errSig.set("Table name is required to browse rows.");
      renderAlert();
      return null;
    }
    if (!isValidPaginationStrings(page, limit)) {
      errSig.set("ADR-025c pagination validation failed: page >= 1 and 1 <= limit <= 100 exact integer strings required.");
      renderAlert();
      return null;
    }
    const payload = {
      target: currentTarget(),
      table,
      page,
      limit,
      sort_col: (sortColInput.value || "").trim(),
      sort_dir: sortDirSelect.value || "ASC",
      filter_col: (filterColInput.value || "").trim(),
      filter_op: filterOpSelect.value || "contains",
      filter_val: filterValInput.value || "",
    };
    const wireCheck = assertExactWireNumbers(payload);
    if (!wireCheck.ok) {
      errSig.set(`ADR-025c violation on ${wireCheck.invalidKeys.join(", ")}`);
      renderAlert();
      return null;
    }
    try {
      const res = await api.post("/api/db/rows", payload);
      rowsSig.set(res);
      renderRowsBrowser();
      statusSig.set(`Loaded page ${res.page} of ${res.table} (${res.total_rows} total rows).`);
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Failed to load rows");
      renderAlert();
      return null;
    }
  };

  const runReadOnlyQuery = async () => {
    errSig.set("");
    statusSig.set("");
    const sql = (sqlInput.value || "").trim();
    if (!sql) {
      errSig.set("Enter a SELECT, SHOW, DESCRIBE, or EXPLAIN SQL query first.");
      renderAlert();
      return null;
    }
    try {
      const res = await api.post("/api/db/query", { target: currentTarget(), sql });
      querySig.set(res);
      renderQueryResults();
      statusSig.set(`Read-only ${res.verb} executed cleanly (${res.row_count} rows${res.truncated ? ", capped at 100" : ""}).`);
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Read-only query blocked or failed");
      renderAlert();
      return null;
    }
  };

  const planMutation = async () => {
    errSig.set("");
    statusSig.set("");
    const sql = (sqlInput.value || "").trim();
    if (!sql) {
      errSig.set("Enter an INSERT, UPDATE, DELETE, DDL, or import SQL statement to preview.");
      renderAlert();
      return null;
    }
    try {
      const res = await api.post("/api/db/mutate/plan", { target: currentTarget(), sql });
      planSig.set(res);
      renderApprovalCard();
      statusSig.set(`Pre-Mutation Snapshot ${res.snapshot_id} captured cleanly. Confirm approval below to execute.`);
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Mutation preview failed");
      renderAlert();
      return null;
    }
  };

  const executeMutation = async () => {
    const plan = planSig.get();
    if (!plan || !plan.approval_token) return null;
    errSig.set("");
    try {
      const res = await api.post("/api/db/mutate/execute", { approval_token: plan.approval_token });
      planSig.set(null);
      renderApprovalCard();
      if (Array.isArray(res.snapshots)) {
        snapshotsSig.set(res.snapshots);
        renderSnapshots();
      }
      statusSig.set(
        `Approved mutation executed cleanly (affected rows: ${res.execution ? res.execution.affected_rows : "0"}). Snapshot ${res.snapshot_id} ready for 1-click rollback.`
      );
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Mutation execution failed");
      renderAlert();
      return null;
    }
  };

  const exportSql = async () => {
    errSig.set("");
    statusSig.set("");
    try {
      const table = (tableInput.value || selectedTableSig.get() || "").trim();
      const res = await api.post("/api/db/export", { target: currentTarget(), table, save_file: false });
      exportSig.set(res);
      setSafeText(exportPre, res.sql_dump || "");
      statusSig.set(`Sanitized SQL export ready (${res.row_count} rows, ${res.sha256}).`);
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "SQL export failed");
      renderAlert();
      return null;
    }
  };

  const refreshSnapshots = async () => {
    try {
      const res = await api.get("/api/db/snapshots");
      if (Array.isArray(res.snapshots)) {
        snapshotsSig.set(res.snapshots);
        renderSnapshots();
      }
      return res;
    } catch {
      return null;
    }
  };

  const restoreSnapshot = async (snapshotId, approvalToken) => {
    errSig.set("");
    try {
      const res = await api.post("/api/db/snapshots/restore", {
        snapshot_id: snapshotId,
        approval_token: approvalToken,
      });
      if (Array.isArray(res.snapshots)) {
        snapshotsSig.set(res.snapshots);
        renderSnapshots();
      }
      statusSig.set(
        `Pre-Mutation Snapshot ${snapshotId} restored cleanly (${res.restore ? res.restore.restored_rows : "0"} rows restored).`
      );
      renderAlert();
      return res;
    } catch (e) {
      errSig.set(e.message || "Pre-Mutation Snapshot restore failed");
      renderAlert();
      return null;
    }
  };

  inspectBtn.addEventListener("click", () => {
    loadSchema().catch(() => {});
  });
  refreshTargetsBtn.addEventListener("click", () => {
    refreshTargets().catch(() => {});
  });
  exportBtn.addEventListener("click", () => {
    exportSql().catch(() => {});
  });
  browseBtn.addEventListener("click", () => {
    browseRows().catch(() => {});
  });
  prevPageBtn.addEventListener("click", () => {
    const cur = Number.parseInt(pageInput.value || "1", 10) || 1;
    if (cur > 1) {
      pageInput.value = String(cur - 1);
      browseRows().catch(() => {});
    }
  });
  nextPageBtn.addEventListener("click", () => {
    const cur = Number.parseInt(pageInput.value || "1", 10) || 1;
    const maxP = Number.parseInt((rowsSig.get() && rowsSig.get().total_pages) || "1", 10) || 1;
    if (cur < maxP) {
      pageInput.value = String(cur + 1);
      browseRows().catch(() => {});
    }
  });
  runReadBtn.addEventListener("click", () => {
    runReadOnlyQuery().catch(() => {});
  });
  planMutateBtn.addEventListener("click", () => {
    planMutation().catch(() => {});
  });

  renderTargets();
  renderSchemaExplorer();
  renderRowsBrowser();
  renderQueryResults();
  renderApprovalCard();
  renderSnapshots();

  return {
    element: section,
    refreshTargets,
    loadSchema,
    browseRows,
    runReadOnlyQuery,
    planMutation,
    executeMutation,
    exportSql,
    refreshSnapshots,
    restoreSnapshot,
    setTargets(items) {
      if (Array.isArray(items) && items.length > 0) {
        targetsSig.set(items);
        renderTargets();
      }
    },
    setSnapshots(items) {
      if (Array.isArray(items)) {
        snapshotsSig.set(items);
        renderSnapshots();
      }
    },
    getState() {
      return {
        targets: targetsSig.get(),
        schema: schemaSig.get(),
        selectedTable: selectedTableSig.get(),
        rows: rowsSig.get(),
        query: querySig.get(),
        pendingPlan: planSig.get(),
        snapshots: snapshotsSig.get(),
        status: statusSig.get(),
        error: errSig.get(),
      };
    },
  };
}
