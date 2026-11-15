import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { auditAccessibility, auditDom } from "../public/gashboard/grex.js";
import { mountGashboardDashboard, SAMPLE_VPS_NODES } from "../public/gashboard/dashboard.js";
import { DomDocument } from "./helpers/dom-shim.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

function createMockFetch(csrfExpected) {
  const nodes = SAMPLE_VPS_NODES.map((n) => ({ ...n }));
  const tunnels = [];
  const snapshots = [];
  const approvals = new Map();
  let reqCount = 0;

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
    throw new Error(`Unexpected mock request: ${method} ${url}`);
  };
}

test("templates and custom UI JS modules contain zero <div> tags and zero unsafe DOM writes", () => {
  const viewPath = path.join(REPO_ROOT, "views", "dashboard.grab.html");
  const viewHtml = fs.readFileSync(viewPath, "utf8");
  assert.equal(/<\s*\/?\s*div\b/i.test(viewHtml), false, "dashboard.grab.html must have zero <div> elements");
  assert.equal(/\.innerHTML/i.test(viewHtml), false, "dashboard.grab.html must have zero .innerHTML references");

  const jsFiles = ["api-client.js", "marketplace.js", "tunnels.js", "fleet-dna.js", "dashboard.js"];
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

test("Gashboard dashboard mounts with 0 <div>s, 0 innerHTML writes, and 100% WCAG AA pass", async () => {
  const doc = new DomDocument();
  const root = doc.createElement("main");
  root.setAttribute("id", "gashboard-root");
  doc.body.appendChild(root);

  const csrfToken = "csrf-unit-test-token";
  const handle = mountGashboardDashboard({
    root,
    document: doc,
    csrfToken,
    fetchImpl: createMockFetch(csrfToken),
  });

  const audit = handle.auditDomSafety();
  assert.equal(audit.divCount, 0, "Mounted Gashboard DOM must contain zero <div> elements");
  assert.equal(audit.innerHTMLWriteCount, 0, "Mounted Gashboard UI must perform zero innerHTML writes");
  assert.equal(audit.a11yOk, true, `WCAG accessibility issues: ${JSON.stringify(audit.a11yIssues)}`);
  assert.equal(doc.querySelectorAll("div").length, 0);

  // Full interactive end-to-end UI simulation
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

  // Re-run full DOM audit after all dynamic updates
  const postAudit = auditDom(root);
  assert.equal(postAudit.ok, true, `Post-interaction DOM a11y issues: ${JSON.stringify(postAudit.issues)}`);
  assert.equal(doc.innerHTMLWriteCount, 0);
  assert.equal(root.querySelectorAll("div").length, 0);

  // Reject unpinned SSH fingerprint before any POST
  doc.getElementById("gash-vps-fp").value = "bad-unpinned-fingerprint";
  await assert.rejects(() => handle.registerVps(), /known_hosts pinning/i);
});

test("Gashboard CSS color pairs satisfy WCAG AA contrast (>= 4.5:1) via Grex auditAccessibility()", () => {
  const pairs = [
    ["Light primary text", "#0f172a", "#f8fafc"],
    ["Light surface text", "#0f172a", "#ffffff"],
    ["Light muted text", "#475569", "#ffffff"],
    ["Primary button", "#ffffff", "#047857"],
    ["Light danger alert", "#991b1b", "#fef2f2"],
    ["Light pass alert", "#065f46", "#ecfdf5"],
    ["Dark primary text", "#f8fafc", "#0f172a"],
    ["Dark surface text", "#f8fafc", "#1e293b"],
    ["Dark muted text", "#cbd5e1", "#1e293b"],
    ["Dark danger alert", "#fecaca", "#7f1d1d"],
    ["Dark pass alert", "#d1fae5", "#064e3b"],
  ];

  for (const [label, color, bg] of pairs) {
    const res = auditAccessibility({
      type: "Text",
      props: { text: label },
      styles: { base: { color, "background-color": bg } },
    });
    assert.equal(res.ok, true, `${label} failed WCAG AA: ${JSON.stringify(res.issues)}`);
  }
});
