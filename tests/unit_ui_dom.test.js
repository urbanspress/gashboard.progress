import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { auditAccessibility, auditDom, computeContrastRatio } from "../public/gashboard/grex.js";
import { mountGashboardDashboard, SAMPLE_VPS_NODES } from "../public/gashboard/dashboard.js";
import { THEME_PALETTES, verifyThemeWcagContrast } from "../public/gashboard/theme.js";
import { DomDocument } from "./helpers/dom-shim.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

function createMockFetch(csrfExpected) {
  const nodes = SAMPLE_VPS_NODES.map((n) => ({ ...n }));
  const tunnels = [];
  const snapshots = [];
  const dbSnapshots = [];
  const approvals = new Map();
  let activeTheme = "light";
  const dbRowsState = [
    { id: "9007199254740993", sku: "SKU-ALPHA", amount_exact: "12345678901234567890.1234", qty: "42" },
    { id: "9007199254740995", sku: "SKU-BETA", amount_exact: "99.9500", qty: "7" },
  ];
  let reqCount = 0;
  let dnsVault = { configured: false, provider: "namecheap", api_user_masked: "", client_ip_masked: "", client_ip: "", sandbox: true, vault_cipher: "AES-256-GCM", api_key_configured: false };
  const dnsSnapshots = [];
  const httpsRollouts = [];
  const dnsPropState = { propagated: false };

  return async (url, init = {}) => {
    reqCount += 1;
    const method = (init.method || "GET").toUpperCase();
    const hdrs = init.headers || {};
    if (method !== "GET" && method !== "HEAD") {
      if (hdrs["X-CSRF-Token"] !== csrfExpected) {
        return {
          ok: false,
          status: 403,
          text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid CSRF token" }),
        };
      }
    }
    const body = init.body ? JSON.parse(init.body) : {};

    if (url === "/api/preferences/theme" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, theme: activeTheme }) };
    }
    if (url === "/api/preferences/theme" && method === "POST") {
      if (body.theme !== "light" && body.theme !== "dark") {
        return { ok: false, status: 422, text: async () => JSON.stringify({ ok: false, code: "GASH-E422", error: "Invalid theme" }) };
      }
      activeTheme = body.theme;
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, theme: activeTheme }) };
    }
    if (url === "/api/db/targets" && method === "GET") {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            targets: [
              {
                target_id: "sqlite:gashboard.db",
                label: "Confined Workspace SQLite (gashboard.db)",
                engine: "sqlite",
                sqlite_path: "gashboard.db",
              },
            ],
          }),
      };
    }
    if (url === "/api/db/schema" && method === "POST") {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            engine: "sqlite",
            target_label: "gashboard.db",
            databases: ["main"],
            tables: [
              {
                name: "invoices",
                schema: "main",
                row_count: String(dbRowsState.length),
                columns: [
                  { name: "id", type: "INTEGER", nullable: false, primary_key: true },
                  { name: "sku", type: "TEXT", nullable: false, primary_key: false },
                  { name: "amount_exact", type: "TEXT", nullable: false, primary_key: false },
                  { name: "qty", type: "INTEGER", nullable: false, primary_key: false },
                ],
                indexes: [{ name: "idx_invoices_sku", unique: false, columns: ["sku"] }],
                foreign_keys: [],
              },
            ],
          }),
      };
    }
    if (url === "/api/db/rows" && method === "POST") {
      const lNum = Number.parseInt(String(body.limit || "25"), 10);
      if (lNum > 100 || lNum < 1) {
        return { ok: false, status: 422, text: async () => JSON.stringify({ ok: false, code: "GASH-E422", error: "limit <= 100 required" }) };
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            engine: "sqlite",
            table: body.table || "invoices",
            page: String(body.page || "1"),
            limit: String(body.limit || "25"),
            total_rows: String(dbRowsState.length),
            total_pages: "1",
            columns: [
              { name: "id", type: "INTEGER", nullable: false },
              { name: "sku", type: "TEXT", nullable: false },
              { name: "amount_exact", type: "TEXT", nullable: false },
              { name: "qty", type: "INTEGER", nullable: false },
            ],
            rows: dbRowsState.map((r) => ({ ...r })),
          }),
      };
    }
    if (url === "/api/db/query" && method === "POST") {
      const upper = String(body.sql || "").trim().toUpperCase();
      if (!upper.startsWith("SELECT") && !upper.startsWith("EXPLAIN") && !upper.startsWith("SHOW")) {
        return {
          ok: false,
          status: 403,
          text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Read-only runner blocked write statement" }),
        };
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            engine: "sqlite",
            verb: "SELECT",
            read_only: true,
            truncated: false,
            row_count: String(dbRowsState.length),
            columns: [
              { name: "id", type: "INTEGER" },
              { name: "sku", type: "TEXT" },
              { name: "amount_exact", type: "TEXT" },
              { name: "qty", type: "INTEGER" },
            ],
            rows: dbRowsState.map((r) => ({ ...r })),
          }),
      };
    }
    if (url === "/api/db/mutate/plan" && method === "POST") {
      const snapId = `dbsnap_mock_${reqCount}`;
      const tok = `apprv-db-mut-${reqCount}`;
      approvals.set(tok, { used: false, kind: "db_mutate", snapId, sql: body.sql, backupRows: dbRowsState.map((r) => ({ ...r })) });
      const snapRec = {
        id: snapId,
        target_id: "sqlite:gashboard.db",
        target_kind: "sqlite",
        table_name: "invoices",
        statement_preview: `Mutation preview on invoices`,
        snapshot_path: `snapshots/${snapId}.json`,
        backup_sha256: "sha256:abcdef1234567890",
        status: "planned",
        created_at: "2026-11-15T06:00:00Z",
        restored_at: "",
      };
      dbSnapshots.unshift(snapRec);
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            snapshot_id: snapId,
            target_id: "sqlite:gashboard.db",
            engine: "sqlite",
            kind: "dml",
            verb: "DELETE",
            table_name: "invoices",
            statement_count: "1",
            pre_row_count: String(dbRowsState.length),
            plain_summary: "Row mutation (DELETE on invoices)",
            snapshot_path: snapRec.snapshot_path,
            backup_sha256: snapRec.backup_sha256,
            approval_token: tok,
          }),
      };
    }
    if (url === "/api/db/mutate/execute" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "db_mutate") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid approval_token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "approval_token already consumed" }) };
      }
      rec.used = true;
      dbRowsState.pop();
      const rbTok = `apprv-db-rb-${reqCount}`;
      approvals.set(rbTok, { used: false, kind: "db_restore", snapId: rec.snapId, backupRows: rec.backupRows });
      const snap = dbSnapshots.find((s) => s.id === rec.snapId);
      if (snap) {
        snap.status = "executed";
        snap.restore_approval_token = rbTok;
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            execution: { ok: true, affected_rows: "1", snapshot_id: rec.snapId },
            snapshot_id: rec.snapId,
            restore_approval_token: rbTok,
            snapshots: dbSnapshots,
          }),
      };
    }
    if (url === "/api/db/export" && method === "POST") {
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            engine: "sqlite",
            sql_dump: "INSERT INTO \"invoices\" VALUES ('9007199254740993', 'SKU-ALPHA', '12345678901234567890.1234', 42);",
            sha256: "sha256:exportok",
            table_count: "1",
            row_count: String(dbRowsState.length),
          }),
      };
    }
    if (url === "/api/db/snapshots" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, snapshots: dbSnapshots, audits: [] }) };
    }
    if (url === "/api/db/snapshots/restore" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "db_restore") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid restore approval_token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "restore token already used" }) };
      }
      rec.used = true;
      dbRowsState.splice(0, dbRowsState.length, ...rec.backupRows.map((r) => ({ ...r })));
      const snap = dbSnapshots.find((s) => s.id === body.snapshot_id);
      if (snap) {
        snap.status = "restored";
        delete snap.restore_approval_token;
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            restore: { ok: true, snapshot_id: body.snapshot_id, restored_rows: String(dbRowsState.length), status: "restored" },
            snapshots: dbSnapshots,
          }),
      };
    }

    if (url === "/api/vps" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, nodes }) };
    }
    if (url === "/api/vps/register" && method === "POST") {
      const created = {
        id: `vps-mock-${nodes.length + 1}`,
        label: body.label,
        host: body.host,
        ssh_port: body.ssh_port || "22",
        ssh_user: body.ssh_user || "deploy",
        host_key_fingerprint: body.host_key_fingerprint,
        environment: body.environment || "production",
        edge_proxy: body.edge_proxy || "caddy",
        domain: body.domain || "shop.example.com",
        cpu_pct: body.cpu_pct || "10.00",
        ram_gb: body.ram_gb || "4.00",
        disk_gb: body.disk_gb || "80.00",
        grisp_workers: body.grisp_workers || "2",
        status: "healthy",
      };
      nodes.push(created);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, node: created }) };
    }
    if (url.startsWith("/api/vps/") && url.endsWith("/probe") && method === "POST") {
      const id = decodeURIComponent(url.split("/")[3]);
      const node = nodes.find((n) => n.id === id) || nodes[0];
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, node, ready_status: "200" }) };
    }
    if (url === "/api/marketplace/catalog" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, blueprints: [] }) };
    }
    if (url === "/api/marketplace/plan" && method === "POST") {
      const tok = `apprv-mp-${reqCount}`;
      approvals.set(tok, { used: false, ...body });
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            plan_id: `plan-${reqCount}`,
            ...body,
            read_only: true,
            doctor_status: "pass",
            approval_token: tok,
          }),
      };
    }
    if (url === "/api/marketplace/deploy" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec) {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, error: "Invalid approval_token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, error: "Token consumed" }) };
      }
      rec.used = true;
      const snapId = `snap-mp-${reqCount}`;
      snapshots.unshift({
        snapshot_id: snapId,
        node_id: rec.node_id,
        dna_digest: "sha256:mpdemo",
        lock_digest: "grabman.lock:verified",
        ready_status: "200",
        created_at: "2026-11-15T03:00:00Z",
        rollback_token: `apprv-rb-${reqCount}`,
      });
      approvals.set(`apprv-rb-${reqCount}`, { used: false, snapshot_id: snapId });
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            install: {
              id: `inst-${reqCount}`,
              node_id: rec.node_id,
              blueprint_id: rec.blueprint_id,
              domain: rec.domain,
              edge_proxy: rec.edge_proxy,
              snapshot_id: snapId,
            },
          }),
      };
    }
    if (url === "/api/tunnels" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, tunnels }) };
    }
    if (url === "/api/tunnels/open" && method === "POST") {
      const tun = {
        id: `tun-mock-${reqCount}`,
        node_id: body.node_id,
        engine: body.engine,
        local_host: "127.0.0.1",
        local_port: body.local_port === "0" ? "15432" : body.local_port,
        expires_at: "2026-11-15T04:00:00Z",
      };
      tunnels.push(tun);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, tunnel: tun }) };
    }
    if (url === "/api/tunnels/close" && method === "POST") {
      const idx = tunnels.findIndex((t) => t.id === body.id);
      if (idx >= 0) tunnels.splice(idx, 1);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, closed_id: body.id }) };
    }
    if (url === "/api/fleet/snapshots" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, snapshots }) };
    }
    if (url === "/api/fleet/dna/preview" && method === "POST") {
      const tok = `apprv-dna-${reqCount}`;
      approvals.set(tok, { used: false, ...body });
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            preview_id: `prev-${reqCount}`,
            site_name: body.site_dna?.site_name || "Urban Press Studio",
            active_style_pack: body.site_dna?.active_style_pack || "emerald-editorial",
            dna_digest: "sha256:dna123",
            lock_digest: "grabman.lock:verified",
            lock_verified: true,
            approval_token: tok,
          }),
      };
    }
    if (url === "/api/fleet/dna/deploy" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      rec.used = true;
      const snapId = `snap-dna-${reqCount}`;
      const rbTok = `apprv-rb-${reqCount}`;
      approvals.set(rbTok, { used: false, snapshot_id: snapId });
      const dep = {
        id: `dep-${reqCount}`,
        snapshot_id: snapId,
        node_id: rec.node_id,
        dna_digest: "sha256:dna123",
        lock_digest: "grabman.lock:verified",
        ready_status: "200",
        created_at: "2026-11-15T03:05:00Z",
        rollback_token: rbTok,
      };
      snapshots.unshift(dep);
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ ok: true, deployment: dep, rollback_approval_token: rbTok, snapshots }),
      };
    }
    if (url === "/api/fleet/rollback" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      assert.ok(rec && !rec.used, "Expected valid unconsumed rollback approval_token");
      rec.used = true;
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            rollback: { snapshot_id: body.snapshot_id, node_id: body.node_id, ready_status: "200" },
            snapshots,
          }),
      };
    }
    if (url === "/api/dns/namecheap/status" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, ...dnsVault }) };
    }
    if (url === "/api/dns/namecheap/save" && method === "POST") {
      if (!body.api_user || !body.api_key || !body.client_ip) {
        return { ok: false, status: 422, text: async () => JSON.stringify({ ok: false, code: "GASH-E422", error: "Missing Namecheap fields" }) };
      }
      dnsVault = {
        configured: true,
        provider: "namecheap",
        api_user_masked: `${body.api_user.slice(0, 2)}***${body.api_user.slice(-2)}`,
        client_ip_masked: "203.0.***.5",
        client_ip: "203.0.***.5",
        sandbox: Boolean(body.sandbox),
        vault_cipher: "AES-256-GCM",
        api_key_configured: true,
      };
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, ...dnsVault }) };
    }
    if (url === "/api/dns/plan" && method === "POST") {
      const tok = `apprv-dns-${reqCount}`;
      const plan = {
        domain: body.domain || "example.com",
        root_domain: "example.com",
        subdomain: body.subdomain || "@",
        target_ip: body.target_ip || "198.51.100.24",
        ttl: String(body.ttl || "300"),
        preserved_email_count: "2",
        preserved_other_count: "1",
        backup_sha256: "sha256:dnsbackup123",
        plain_summary: "Configure example.com (A -> 198.51.100.24) while preserving 2 email/TXT records and 1 unrelated host record intact.",
        diffs: [
          { action: "keep_email", name: "@", type: "MX", previous_address: "mail.protonmail.ch.", next_address: "mail.protonmail.ch.", ttl: "1800", reason: "Preserved intact (email/verification record)" },
          { action: "keep_email", name: "@", type: "TXT", previous_address: "v=spf1 include:_spf.protonmail.ch ~all", next_address: "v=spf1 include:_spf.protonmail.ch ~all", ttl: "1800", reason: "Preserved intact (email/verification record)" },
          { action: "update", name: "@", type: "A", previous_address: "198.51.100.10", next_address: body.target_ip || "198.51.100.24", ttl: String(body.ttl || "300"), reason: "Point web root to target VPS IP" },
        ],
      };
      approvals.set(tok, { used: false, kind: "dns_apply", plan, body });
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, plan_id: `dnsplan-${reqCount}`, plan, approval_token: tok }) };
    }
    if (url === "/api/dns/apply" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "dns_apply") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid DNS approval_token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "approval_token has already been consumed" }) };
      }
      rec.used = true;
      const snapId = `dnssnap-${reqCount}`;
      const rbTok = `apprv-dns-rb-${reqCount}`;
      approvals.set(rbTok, { used: false, kind: "dns_rollback", snapshot_id: snapId, domain: rec.plan.domain });
      const snap = {
        id: snapId,
        domain: rec.plan.domain,
        subdomain: rec.plan.subdomain,
        target_ip: rec.plan.target_ip,
        preserved_email_count: "2",
        status: "applied",
        rollback_token: rbTok,
      };
      dnsSnapshots.unshift(snap);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, dns_snapshot_id: snapId, snapshot: snap, result: rec.plan, rollback_approval_token: rbTok, snapshots: dnsSnapshots }) };
    }
    if (url === "/api/dns/snapshots" && method === "GET") {
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, snapshots: dnsSnapshots, rollouts: httpsRollouts }) };
    }
    if (url === "/api/dns/rollback" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "dns_rollback") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid DNS rollback token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "DNS rollback token already consumed" }) };
      }
      rec.used = true;
      const snap = dnsSnapshots.find((s) => s.id === body.dns_snapshot_id);
      if (snap) {
        snap.status = "rolled_back";
        delete snap.rollback_token;
      }
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, rollback: { dns_snapshot_id: body.dns_snapshot_id, domain: snap?.domain, status: "rolled_back" }, snapshots: dnsSnapshots }) };
    }
    if (url === "/api/dns/propagation/check" && method === "POST") {
      const propagated = dnsPropState.propagated || body.edge_proxy === "cloudflare-tunnel";
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            ok: true,
            propagation: {
              domain: body.domain,
              expected_ip: body.expected_ip,
              propagated,
              message: propagated
                ? `DNS propagation verified for ${body.domain} -> ${body.expected_ip}`
                : `DNS not propagated yet for ${body.domain}: Let's Encrypt issuance blocked.`,
            },
          }),
      };
    }
    if (url === "/api/https/plan" && method === "POST") {
      if (!dnsPropState.propagated && body.edge_proxy !== "cloudflare-tunnel") {
        return { ok: false, status: 422, text: async () => JSON.stringify({ ok: false, code: "GASH-E422", error: "DNS has not propagated yet: blocking Let's Encrypt issuance to prevent rate-limit lockouts." }) };
      }
      const tok = `apprv-https-${reqCount}`;
      const plan = {
        plan_id: `hplan-${reqCount}`,
        node_id: body.node_id,
        domain: body.domain,
        expected_ip: body.expected_ip,
        edge_proxy: body.edge_proxy || "caddy",
        workspace: body.workspace || "./site",
        dns_snapshot_id: body.dns_snapshot_id || "",
        workers: String(body.workers || "2"),
      };
      approvals.set(tok, { used: false, kind: "https_apply", plan });
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, ready_for_tls: true, propagation: { propagated: true, message: `Verified ${body.domain} -> ${body.expected_ip}` }, plan, approval_token: tok }) };
    }
    if (url === "/api/https/apply" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "https_apply") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid HTTPS approval_token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "HTTPS approval_token already consumed" }) };
      }
      rec.used = true;
      const rId = `https-${reqCount}`;
      const rbTok = `apprv-https-rb-${reqCount}`;
      approvals.set(rbTok, { used: false, kind: "https_rollback", rollout_id: rId });
      const ro = {
        id: rId,
        node_id: rec.plan.node_id,
        domain: rec.plan.domain,
        edge_proxy: rec.plan.edge_proxy,
        dns_snapshot_id: rec.plan.dns_snapshot_id,
        ready_status: "200",
        tls_verified: 1,
        status: "active",
        rollback_token: rbTok,
      };
      httpsRollouts.unshift(ro);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, rollout: ro, verify: { ready_status: "200", tls_verified: true }, rollback_approval_token: rbTok, rollouts: httpsRollouts }) };
    }
    if (url === "/api/https/rollback" && method === "POST") {
      const rec = approvals.get(body.approval_token);
      if (!rec || rec.kind !== "https_rollback") {
        return { ok: false, status: 403, text: async () => JSON.stringify({ ok: false, code: "GASH-E403", error: "Invalid HTTPS rollback token" }) };
      }
      if (rec.used) {
        return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, code: "GASH-E409", error: "HTTPS rollback token already consumed" }) };
      }
      rec.used = true;
      const ro = httpsRollouts.find((r) => r.id === body.rollout_id);
      if (ro) {
        ro.status = "rolled_back";
        delete ro.rollback_token;
        if (body.rollback_dns && body.dns_approval_token && ro.dns_snapshot_id) {
          const dRec = approvals.get(body.dns_approval_token);
          assert.ok(dRec && !dRec.used && dRec.kind === "dns_rollback");
          dRec.used = true;
          const dSnap = dnsSnapshots.find((s) => s.id === ro.dns_snapshot_id);
          if (dSnap) {
            dSnap.status = "rolled_back";
            delete dSnap.rollback_token;
          }
        }
      }
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true, rollback: { rollout_id: body.rollout_id, status: "rolled_back" }, rollouts: httpsRollouts, dns_snapshots: dnsSnapshots }) };
    }
    if (url === "/__test/set_propagated" && method === "POST") {
      dnsPropState.propagated = Boolean(body.propagated);
      return { ok: true, status: 200, text: async () => JSON.stringify({ ok: true }) };
    }
    throw new Error(`Unexpected mock request: ${method} ${url}`);
  };
}

test("templates and custom UI JS modules contain zero <div> tags and zero unsafe DOM writes", () => {
  const viewPath = path.join(REPO_ROOT, "views", "dashboard.grab.html");
  const viewHtml = fs.readFileSync(viewPath, "utf8");
  assert.equal(/<\s*\/?\s*div\b/i.test(viewHtml), false, "dashboard.grab.html must have zero <div> elements");
  assert.equal(/\.innerHTML/i.test(viewHtml), false, "dashboard.grab.html must have zero .innerHTML references");

  const jsFiles = [
    "api-client.js",
    "theme.js",
    "marketplace.js",
    "tunnels.js",
    "fleet-dna.js",
    "dns-https-wizard.js",
    "db-manager.js",
    "dashboard.js",
  ];
  for (const name of jsFiles) {
    const src = fs.readFileSync(path.join(REPO_ROOT, "public", "gashboard", name), "utf8");
    // Strip JS comments before scanning for <div> or .innerHTML usage in code.
    const codeOnly = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    assert.equal(/createElement\(\s*["']div["']\s*\)/i.test(codeOnly), false, `${name} must not create <div>`);
    assert.equal(/\.innerHTML\s*=/.test(codeOnly), false, `${name} must not assign innerHTML`);
    assert.equal(/\beval\s*\(|new\s+Function\s*\(/i.test(codeOnly), false, `${name} must not invoke dynamic eval`);
    assert.equal(/javascript:/i.test(codeOnly), false, `${name} must not contain javascript: URLs`);
  }
});

test("Gashboard dashboard mounts with 0 <div>s, 0 innerHTML writes, Light/Dark WCAG AA toggle, and Visual DB Manager", async () => {
  const doc = new DomDocument();
  doc.documentElement.setAttribute("data-grex-theme", "light");
  const header = doc.createElement("header");
  const toggleBtn = doc.createElement("button");
  toggleBtn.setAttribute("type", "button");
  toggleBtn.setAttribute("id", "gashboard-theme-toggle");
  toggleBtn.textContent = "Switch to Dark Mode";
  header.appendChild(toggleBtn);
  doc.body.appendChild(header);

  const root = doc.createElement("main");
  root.setAttribute("id", "gashboard-root");
  doc.body.appendChild(root);

  const csrfToken = "csrf-unit-test-token";
  const mockFetchImpl = createMockFetch(csrfToken);
  const handle = mountGashboardDashboard({
    root,
    document: doc,
    csrfToken,
    fetchImpl: mockFetchImpl,
  });

  const audit = handle.auditDomSafety();
  assert.equal(audit.divCount, 0, "Mounted Gashboard DOM must contain zero <div> elements");
  assert.equal(audit.innerHTMLWriteCount, 0, "Mounted Gashboard UI must perform zero innerHTML writes");
  assert.equal(audit.a11yOk, true, `WCAG accessibility issues: ${JSON.stringify(audit.a11yIssues)}`);
  assert.equal(doc.querySelectorAll("div").length, 0);

  // Light <-> Dark Theme Switcher persistence & Grex data-grex-theme verification
  assert.equal(handle.theme.getTheme(), "light");
  assert.equal(doc.documentElement.getAttribute("data-grex-theme"), "light");
  const darkRes = await handle.theme.toggle();
  assert.equal(darkRes, "dark");
  assert.equal(doc.documentElement.getAttribute("data-grex-theme"), "dark");
  assert.equal(toggleBtn.getAttribute("aria-pressed"), "true");
  assert.equal(toggleBtn.textContent, "Switch to Light Mode");

  // Full interactive end-to-end UI simulation + Visual DB Manager flows
  const regRes = await handle.registerVps();
  assert.equal(regRes.ok, true);
  assert.equal(handle.getNodes().length, 3);
  assert.equal(doc.getElementById("gash-stat-nodes").textContent, "3");

  const probeRes = await handle.probeNode("vps-prod-01");
  assert.equal(probeRes.ready_status, "200");

  const planRes = await handle.marketplace.runPlan();
  assert.equal(planRes.read_only, true);
  const deployRes = await handle.marketplace.runDeploy();
  assert.equal(deployRes.install.blueprint_id, "grablab-grex-bundle");

  const tunOpen = await handle.tunnels.openTunnel();
  assert.equal(tunOpen.tunnel.local_host, "127.0.0.1");
  await handle.tunnels.closeTunnel(tunOpen.tunnel.id);
  assert.equal(handle.tunnels.getTunnels().length, 0);

  const dnaPrev = await handle.fleetDna.previewDna();
  assert.equal(dnaPrev.lock_verified, true);
  const dnaDep = await handle.fleetDna.deployDna();
  assert.equal(dnaDep.deployment.ready_status, "200");
  const rbRes = await handle.fleetDna.triggerRollback(dnaDep.deployment.snapshot_id);
  assert.equal(rbRes.rollback.ready_status, "200");

  // Visual DB Manager: schema -> exact ADR-025c paginated rows -> read-only block -> Plan/Snapshot/Execute -> 1-Click Restore
  const scRes = await handle.dbManager.loadSchema();
  assert.equal(scRes.tables[0].name, "invoices");
  const rowRes = await handle.dbManager.browseRows();
  assert.equal(rowRes.rows[0].amount_exact, "12345678901234567890.1234");
  assert.equal(rowRes.rows[0].id, "9007199254740993");

  // Block write inside Read-Only runner
  doc.getElementById("db-sql-input").value = "DELETE FROM invoices WHERE sku = 'SKU-BETA'";
  const blockedQ = await handle.dbManager.runReadOnlyQuery();
  assert.equal(blockedQ, null);
  assert.match(handle.dbManager.getState().error, /blocked/i);

  // Plan + Pre-Mutation Snapshot + Execute + 1-Click Restore
  const mutPlan = await handle.dbManager.planMutation();
  assert.ok(mutPlan.snapshot_id && mutPlan.approval_token);
  const mutExec = await handle.dbManager.executeMutation();
  assert.equal(mutExec.execution.affected_rows, "1");
  const restRes = await handle.dbManager.restoreSnapshot(mutPlan.snapshot_id, mutExec.restore_approval_token);
  assert.equal(restRes.restore.restored_rows, "2");

  // Namecheap DNS + Auto-HTTPS Wizard flow
  const rawSecretKey = "nc-super-secret-apikey-9876";
  doc.getElementById("gash-nc-api-user").value = "aliceops";
  doc.getElementById("gash-nc-api-key").value = rawSecretKey;
  doc.getElementById("gash-nc-client-ip").value = "203.0.113.5";
  const vaultSaveRes = await handle.dnsWizard.saveCredentials();
  assert.equal(vaultSaveRes.configured, true);
  assert.equal(vaultSaveRes.api_user_masked, "al***ps");
  assert.equal(doc.getElementById("gash-nc-api-key").value, "", "Plaintext API key input must be cleared immediately");
  assert.equal(doc.getElementById("gash-nc-vault-status").textContent.includes(rawSecretKey), false, "Secret API key must never appear in DOM");
  assert.match(doc.getElementById("gash-nc-vault-status").textContent, /al\*\*\*ps/);

  const dnsPlanRes = await handle.dnsWizard.previewDns({ domain: "example.com", target_ip: "198.51.100.24", ttl: "300" });
  assert.equal(dnsPlanRes.plan.preserved_email_count, "2");
  assert.equal(dnsPlanRes.plan.diffs.some((d) => d.type === "MX" && d.action === "keep_email"), true);

  const dnsApplyRes = await handle.dnsWizard.applyDns();
  assert.ok(dnsApplyRes.dns_snapshot_id && dnsApplyRes.rollback_approval_token);

  // Propagation guard blocks HTTPS planning prior to propagation (prevents Let's Encrypt lockouts)
  await assert.rejects(() => handle.dnsWizard.planHttps({ domain: "example.com", expected_ip: "198.51.100.24", edge_proxy: "caddy" }), /rate-limit lockouts|not propagated/i);

  // Flip simulated DNS propagation to resolved and complete Caddy Auto-HTTPS + 1-Click Rollback + 409 Replay guard
  await mockFetchImpl("/__test/set_propagated", {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body: JSON.stringify({ propagated: true }),
  });
  const propRes = await handle.dnsWizard.checkPropagation({ domain: "example.com", expected_ip: "198.51.100.24", edge_proxy: "caddy" });
  assert.equal(propRes.propagation.propagated, true);
  const caddyPlan = await handle.dnsWizard.planHttps({ domain: "example.com", expected_ip: "198.51.100.24", edge_proxy: "caddy" });
  assert.equal(caddyPlan.ready_for_tls, true);
  const caddyApply = await handle.dnsWizard.applyHttps();
  assert.equal(caddyApply.rollout.ready_status, "200");
  assert.equal(caddyApply.rollout.edge_proxy, "caddy");
  const caddyRb = await handle.dnsWizard.rollbackHttps(caddyApply.rollout.id, caddyApply.rollback_approval_token, dnsApplyRes.rollback_approval_token);
  assert.equal(caddyRb.rollback.status, "rolled_back");
  assert.equal(caddyRb.dns_snapshots[0].status, "rolled_back");
  await assert.rejects(() => handle.dnsWizard.rollbackHttps(caddyApply.rollout.id, caddyApply.rollback_approval_token), /already consumed/i);

  // Re-run full DOM audit after all dynamic updates
  const postAudit = auditDom(root);
  assert.equal(postAudit.ok, true, `Post-interaction DOM a11y issues: ${JSON.stringify(postAudit.issues)}`);
  assert.equal(doc.innerHTMLWriteCount, 0);
  assert.equal(root.querySelectorAll("div").length, 0);

  // Reject unpinned SSH fingerprint before any POST
  doc.getElementById("gash-vps-fp").value = "bad-unpinned-fingerprint";
  await assert.rejects(() => handle.registerVps(), /known_hosts pinning/i);
});

test("Gashboard Light and Dark color palettes satisfy WCAG AA contrast (>= 4.5:1) via computeContrastRatio & auditAccessibility()", () => {
  for (const [mode, p] of Object.entries(THEME_PALETTES)) {
    const wcag = verifyThemeWcagContrast(mode);
    assert.equal(wcag.ok, true, `${mode} theme contrast checks failed: ${JSON.stringify(wcag.checks)}`);

    const pairs = [
      [`${mode} primary text`, p.text, p.bg],
      [`${mode} surface text`, p.text, p.surface],
      [`${mode} muted text`, p.muted, p.surface],
      [`${mode} link text`, p.link, p.surface],
      [`${mode} primary button`, p.btnFg, p.primary],
      [`${mode} danger button`, p.btnFg, p.dangerBtn],
      [`${mode} danger alert`, p.danger, p.dangerBg],
      [`${mode} warn alert`, p.warn, p.warnBg],
      [`${mode} pass alert`, p.pass, p.passBg],
    ];
    for (const [label, color, bg] of pairs) {
      const ratio = computeContrastRatio(color, bg);
      assert.ok(ratio >= 4.5, `${label} ratio ${ratio} < 4.5:1`);
      const res = auditAccessibility({
        type: "Text",
        props: { text: label },
        styles: { base: { color, "background-color": bg } },
      });
      assert.equal(res.ok, true, `${label} failed WCAG AA: ${JSON.stringify(res.issues)}`);
    }
  }
});
