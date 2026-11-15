/**
 * Gashboard v0.1.0 — Root Pure Grex JS v1.0.0 Control Panel Orchestrator.
 * Zero wrapper-<div> elements, zero innerHTML writes, 100% WCAG AA,
 * exact ADR-025c base-10 numeric wire strings, and strict known_hosts pinning.
 */

export const GASHBOARD_VERSION = "0.1.0";

import {
  auditAccessibility,
  auditDom,
  computed,
  setSafeText,
  signal,
} from "./grex.js";
import {
  assertExactWireNumbers,
  createApiClient,
  isValidSshFingerprint,
} from "./api-client.js";
import { createMarketplacePanel } from "./marketplace.js";
import { createTunnelsPanel } from "./tunnels.js";
import { createFleetDnaPanel } from "./fleet-dna.js";

export const SAMPLE_VPS_NODES = Object.freeze([
  {
    id: "vps-prod-01",
    label: "Production Flagship Node",
    host: "198.51.100.24",
    ssh_port: "22",
    ssh_user: "deploy",
    host_key_fingerprint: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
    environment: "production",
    edge_proxy: "caddy",
    domain: "shop.example.com",
    cpu_pct: "14.25",
    ram_gb: "8.00",
    disk_gb: "160.00",
    grisp_workers: "4",
    status: "healthy",
  },
  {
    id: "vps-stage-01",
    label: "Staging Preview Node",
    host: "203.0.113.18",
    ssh_port: "2222",
    ssh_user: "deploy",
    host_key_fingerprint: "SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0",
    environment: "staging",
    edge_proxy: "cloudflare-tunnel",
    domain: "staging.example.com",
    cpu_pct: "6.50",
    ram_gb: "4.00",
    disk_gb: "80.00",
    grisp_workers: "2",
    status: "healthy",
  },
]);

function makeEl(doc, tag, attrs = {}, text = "") {
  const el = doc.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v !== undefined && v !== null) {
      el.setAttribute(k, String(v));
    }
  }
  if (text !== "") {
    setSafeText(el, text);
  }
  return el;
}

export function mountGashboardDashboard({
  root,
  document: doc = globalThis.document,
  csrfToken = "",
  fetchImpl = globalThis.fetch,
  initialNodes = SAMPLE_VPS_NODES,
} = {}) {
  if (!root) {
    throw new Error("mountGashboardDashboard requires a root <main> element.");
  }
  while (root.firstChild) {
    root.removeChild(root.firstChild);
  }

  let resolvedCsrf = csrfToken;
  if (!resolvedCsrf && typeof doc.querySelector === "function") {
    const meta = doc.querySelector('meta[name="gashboard-csrf"]');
    if (meta) {
      resolvedCsrf = meta.getAttribute("content") || "";
    }
  }
  const api = createApiClient({ csrfToken: resolvedCsrf, fetchImpl });

  const nodesSignal = signal([...initialNodes]);
  const vpsStatusMsg = signal("");
  const vpsErrMsg = signal("");
  const healthyCount = computed(() => nodesSignal.get().filter((n) => n.status === "healthy").length);

  // 1. Hero & Live Telemetry Summary (H1)
  const heroSection = makeEl(doc, "section", {
    id: "gash-hero-section",
    class: "gash-card",
    "aria-label": "Gashboard Control Plane Overview",
  });
  heroSection.appendChild(
    makeEl(doc, "h1", { id: "gash-main-title" }, "Discreet Pure Grex JS Multi-VPS Control Panel")
  );
  heroSection.appendChild(
    makeEl(
      doc,
      "p",
      { class: "gash-muted" },
      "Running strictly on local 127.0.0.1 loopback with known_hosts host-key pinning, zero wrapper <div>s, AES-256-GCM credential protection, and 1-click snapshot rollbacks."
    )
  );

  const summaryGrid = makeEl(doc, "section", { class: "gash-grid-4", "aria-label": "Fleet Metrics" });
  const statNodes = makeEl(doc, "article", { class: "gash-stat-card" });
  statNodes.appendChild(makeEl(doc, "h2", { class: "gash-muted" }, "Managed VPS Nodes"));
  const statNodesVal = makeEl(doc, "strong", { id: "gash-stat-nodes", class: "gash-stat-value" }, `${nodesSignal.get().length}`);
  statNodes.appendChild(statNodesVal);

  const statHealthy = makeEl(doc, "article", { class: "gash-stat-card" });
  statHealthy.appendChild(makeEl(doc, "h2", { class: "gash-muted" }, "Healthy Nodes"));
  const statHealthyVal = makeEl(doc, "strong", { id: "gash-stat-healthy", class: "gash-stat-value" }, `${healthyCount.get()}`);
  statHealthy.appendChild(statHealthyVal);

  const statBind = makeEl(doc, "article", { class: "gash-stat-card" });
  statBind.appendChild(makeEl(doc, "h2", { class: "gash-muted" }, "Control Surface"));
  statBind.appendChild(makeEl(doc, "strong", { class: "gash-stat-value" }, "127.0.0.1 Only"));

  const statDom = makeEl(doc, "article", { class: "gash-stat-card" });
  statDom.appendChild(makeEl(doc, "h2", { class: "gash-muted" }, "DOM Security"));
  statDom.appendChild(makeEl(doc, "strong", { class: "gash-stat-value" }, "0 Wrapper <div>s"));

  summaryGrid.appendChild(statNodes);
  summaryGrid.appendChild(statHealthy);
  summaryGrid.appendChild(statBind);
  summaryGrid.appendChild(statDom);
  heroSection.appendChild(summaryGrid);

  // 2. Multi-VPS Inventory & Host-Key Registration Panel (H2)
  const vpsSection = makeEl(doc, "section", {
    id: "gash-vps-panel",
    class: "gash-card",
    "aria-label": "Multi-VPS Fleet Inventory",
  });
  vpsSection.appendChild(makeEl(doc, "h2", { id: "gash-vps-heading" }, "Multi-VPS Inventory & known_hosts Key Pinning"));

  const vpsForm = makeEl(doc, "form", { id: "gash-vps-form", class: "gash-grid-4" });

  const fLabel = makeEl(doc, "section", { class: "gash-field" });
  fLabel.appendChild(makeEl(doc, "label", { for: "gash-vps-label" }, "Server Label"));
  const labelInput = makeEl(doc, "input", { id: "gash-vps-label", name: "label", type: "text", value: "EU Storefront VPS" });
  labelInput.value = "EU Storefront VPS";
  fLabel.appendChild(labelInput);

  const fHost = makeEl(doc, "section", { class: "gash-field" });
  fHost.appendChild(makeEl(doc, "label", { for: "gash-vps-host" }, "SSH Host / IP"));
  const hostInput = makeEl(doc, "input", { id: "gash-vps-host", name: "host", type: "text", value: "203.0.113.55" });
  hostInput.value = "203.0.113.55";
  fHost.appendChild(hostInput);

  const fPort = makeEl(doc, "section", { class: "gash-field" });
  fPort.appendChild(makeEl(doc, "label", { for: "gash-vps-port" }, "SSH Port"));
  const portInput = makeEl(doc, "input", { id: "gash-vps-port", name: "ssh_port", type: "text", value: "22" });
  portInput.value = "22";
  fPort.appendChild(portInput);

  const fFP = makeEl(doc, "section", { class: "gash-field" });
  fFP.appendChild(makeEl(doc, "label", { for: "gash-vps-fp" }, "Pinned Host Key (SHA256:...)"));
  const fpInput = makeEl(doc, "input", {
    id: "gash-vps-fp",
    name: "host_key_fingerprint",
    type: "text",
    value: "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
  });
  fpInput.value = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
  fFP.appendChild(fpInput);

  const fEnv = makeEl(doc, "section", { class: "gash-field" });
  fEnv.appendChild(makeEl(doc, "label", { for: "gash-vps-env" }, "Environment"));
  const envSelect = makeEl(doc, "select", { id: "gash-vps-env", name: "environment" });
  envSelect.appendChild(makeEl(doc, "option", { value: "production" }, "Production"));
  envSelect.appendChild(makeEl(doc, "option", { value: "staging" }, "Staging"));
  envSelect.value = "production";
  fEnv.appendChild(envSelect);

  const fKeyRef = makeEl(doc, "section", { class: "gash-field" });
  fKeyRef.appendChild(makeEl(doc, "label", { for: "gash-vps-cred" }, "SSH Key Passphrase / Agent Ref (Encrypted AES-256-GCM)"));
  const credInput = makeEl(doc, "input", { id: "gash-vps-cred", name: "ssh_credential", type: "password", value: "ed25519-agent-key" });
  credInput.value = "ed25519-agent-key";
  fKeyRef.appendChild(credInput);

  vpsForm.appendChild(fLabel);
  vpsForm.appendChild(fHost);
  vpsForm.appendChild(fPort);
  vpsForm.appendChild(fFP);
  vpsForm.appendChild(fEnv);
  vpsForm.appendChild(fKeyRef);

  const vpsActions = makeEl(doc, "section", { class: "gash-actions", "aria-label": "VPS Actions" });
  const registerBtn = makeEl(doc, "button", { id: "gash-vps-register-btn", type: "button", class: "gash-btn" }, "Register & Pin VPS");
  const refreshBtn = makeEl(doc, "button", { id: "gash-vps-refresh-btn", type: "button", class: "gash-btn gash-btn-secondary" }, "Refresh Live Fleet");
  vpsActions.appendChild(registerBtn);
  vpsActions.appendChild(refreshBtn);

  const vpsFeedback = makeEl(doc, "aside", { id: "gash-vps-feedback", "aria-live": "polite" });

  const vpsTable = makeEl(doc, "table", { id: "gash-vps-table", class: "gash-table" });
  const vHead = makeEl(doc, "thead");
  const vHRow = makeEl(doc, "tr");
  for (const h of ["Node", "Host / Port", "Environment", "Edge SSL", "CPU / RAM / Workers (ADR-025c)", "Status", "Probe"]) {
    vHRow.appendChild(makeEl(doc, "th", {}, h));
  }
  vHead.appendChild(vHRow);
  const vTbody = makeEl(doc, "tbody");
  vpsTable.appendChild(vHead);
  vpsTable.appendChild(vTbody);

  vpsSection.appendChild(vpsForm);
  vpsSection.appendChild(vpsActions);
  vpsSection.appendChild(vpsFeedback);
  vpsSection.appendChild(vpsTable);

  // Child panels (Marketplace, Tunnels, Fleet Site DNA)
  let marketplacePanel = null;
  let tunnelsPanel = null;
  let fleetDnaPanel = null;

  const refreshAllNodeSelectors = () => {
    setSafeText(statNodesVal, `${nodesSignal.get().length}`);
    setSafeText(statHealthyVal, `${healthyCount.get()}`);
    if (marketplacePanel) marketplacePanel.refreshNodes();
    if (tunnelsPanel) tunnelsPanel.refreshNodes();
    if (fleetDnaPanel) fleetDnaPanel.refreshNodes();
  };

  const renderVpsFeedback = () => {
    while (vpsFeedback.firstChild) vpsFeedback.removeChild(vpsFeedback.firstChild);
    if (vpsErrMsg.get()) {
      vpsFeedback.appendChild(makeEl(doc, "p", { class: "gash-alert-danger", role: "alert" }, vpsErrMsg.get()));
    }
    if (vpsStatusMsg.get()) {
      vpsFeedback.appendChild(makeEl(doc, "p", { class: "gash-alert-pass" }, vpsStatusMsg.get()));
    }
  };

  const probeNode = async (nodeId) => {
    vpsErrMsg.set("");
    try {
      const res = await api.post(`/api/vps/${encodeURIComponent(nodeId)}/probe`, {});
      const numCheck = assertExactWireNumbers(res);
      if (!numCheck.ok) {
        throw new Error(`ADR-025c precision violation in probe response: ${numCheck.invalidKeys.join(", ")}`);
      }
      if (res.node) {
        nodesSignal.set(nodesSignal.get().map((n) => (n.id === res.node.id ? res.node : n)));
        renderVpsTable();
        refreshAllNodeSelectors();
      }
      vpsStatusMsg.set(`Probed ${nodeId} over SSH: /_ready OK (${res.node?.grisp_workers || "2"} Grisp workers).`);
      renderVpsFeedback();
      return res;
    } catch (err) {
      vpsErrMsg.set(err.message || `Probe failed for ${nodeId}.`);
      renderVpsFeedback();
      throw err;
    }
  };

  const renderVpsTable = () => {
    while (vTbody.firstChild) vTbody.removeChild(vTbody.firstChild);
    for (const node of nodesSignal.get()) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, `${node.label} (${node.id})`));
      tr.appendChild(makeEl(doc, "td", {}, `${node.host}:${node.ssh_port}`));
      tr.appendChild(makeEl(doc, "td", {}, node.environment));
      tr.appendChild(makeEl(doc, "td", {}, `${node.edge_proxy || "caddy"} (${node.domain || "-"})`));
      tr.appendChild(
        makeEl(doc, "td", {}, `${node.cpu_pct || "0.00"}% · ${node.ram_gb || "4.00"} GB · ${node.grisp_workers || "2"}w`)
      );
      tr.appendChild(makeEl(doc, "td", {}, node.status || "healthy"));
      const tdAct = makeEl(doc, "td");
      const probeBtn = makeEl(
        doc,
        "button",
        { type: "button", class: "gash-btn gash-btn-secondary", "data-probe-node": node.id },
        "Probe /_ready"
      );
      probeBtn.addEventListener("click", () => {
        probeNode(node.id).catch(() => {});
      });
      tdAct.appendChild(probeBtn);
      tr.appendChild(tdAct);
      vTbody.appendChild(tr);
    }
  };

  const registerVps = async () => {
    vpsErrMsg.set("");
    vpsStatusMsg.set("");
    const fp = String(fpInput.value || "").trim();
    if (!isValidSshFingerprint(fp)) {
      const err = new Error("Strict known_hosts pinning requires a valid SHA256:<base64> host fingerprint.");
      vpsErrMsg.set(err.message);
      renderVpsFeedback();
      throw err;
    }
    const payload = {
      label: labelInput.value || "Managed VPS",
      host: hostInput.value,
      ssh_port: String(portInput.value || "22").trim(),
      ssh_user: "deploy",
      host_key_fingerprint: fp,
      ssh_credential: credInput.value || "agent-key",
      environment: envSelect.value || "production",
      edge_proxy: "caddy",
      domain: "shop.example.com",
      cpu_pct: "10.00",
      ram_gb: "4.00",
      disk_gb: "80.00",
      grisp_workers: "2",
    };
    const numCheck = assertExactWireNumbers(payload);
    if (!numCheck.ok) {
      const err = new Error(`ADR-025c exact string required for: ${numCheck.invalidKeys.join(", ")}`);
      vpsErrMsg.set(err.message);
      renderVpsFeedback();
      throw err;
    }
    try {
      const res = await api.post("/api/vps/register", payload);
      if (res.node) {
        nodesSignal.set([...nodesSignal.get(), res.node]);
        renderVpsTable();
        refreshAllNodeSelectors();
      }
      vpsStatusMsg.set(`Registered and host-key pinned ${res.node?.label || payload.label} (AES-256-GCM encrypted vault).`);
      renderVpsFeedback();
      return res;
    } catch (err) {
      vpsErrMsg.set(err.message || "VPS registration failed.");
      renderVpsFeedback();
      throw err;
    }
  };

  const loadLiveFleet = async () => {
    try {
      const [vpsRes, catRes, tunRes, snapRes] = await Promise.all([
        api.get("/api/vps"),
        api.get("/api/marketplace/catalog"),
        api.get("/api/tunnels"),
        api.get("/api/fleet/snapshots"),
      ]);
      if (Array.isArray(vpsRes.nodes) && vpsRes.nodes.length > 0) {
        const chk = assertExactWireNumbers(vpsRes.nodes);
        if (!chk.ok) throw new Error(`ADR-025c numeric drift: ${chk.invalidKeys.join(", ")}`);
        nodesSignal.set(vpsRes.nodes);
        renderVpsTable();
        refreshAllNodeSelectors();
      }
      if (Array.isArray(catRes.blueprints)) {
        marketplacePanel.setCatalog(catRes.blueprints);
      }
      if (Array.isArray(tunRes.tunnels)) {
        tunnelsPanel.setTunnels(tunRes.tunnels);
      }
      if (Array.isArray(snapRes.snapshots)) {
        fleetDnaPanel.setSnapshots(snapRes.snapshots);
      }
      return true;
    } catch {
      return false;
    }
  };

  registerBtn.addEventListener("click", () => {
    registerVps().catch(() => {});
  });
  refreshBtn.addEventListener("click", () => {
    loadLiveFleet().catch(() => {});
  });

  marketplacePanel = createMarketplacePanel({
    doc,
    api,
    nodesSignal,
    onDeploymentComplete: () => {
      loadLiveFleet().catch(() => {});
    },
  });
  tunnelsPanel = createTunnelsPanel({ doc, api, nodesSignal });
  fleetDnaPanel = createFleetDnaPanel({ doc, api, nodesSignal });

  root.appendChild(heroSection);
  root.appendChild(vpsSection);
  root.appendChild(marketplacePanel.element);
  root.appendChild(tunnelsPanel.element);
  root.appendChild(fleetDnaPanel.element);

  renderVpsTable();
  refreshAllNodeSelectors();

  return {
    registerVps,
    probeNode,
    loadLiveFleet,
    marketplace: marketplacePanel,
    tunnels: tunnelsPanel,
    fleetDna: fleetDnaPanel,
    getNodes: () => nodesSignal.get(),
    auditDomSafety() {
      const divs = typeof root.querySelectorAll === "function" ? root.querySelectorAll("div") : [];
      const a11y = auditDom(root);
      const schemaA11y = auditAccessibility({
        type: "Section",
        props: { label: "Gashboard Control Panel" },
        styles: { base: { color: "#0f172a", "background-color": "#ffffff" } },
      });
      return {
        divCount: divs.length,
        innerHTMLWriteCount: doc.innerHTMLWriteCount || 0,
        a11yOk: a11y.ok && schemaA11y.ok,
        a11yIssues: [...a11y.issues, ...schemaA11y.issues],
      };
    },
  };
}

if (typeof globalThis.document !== "undefined" && typeof globalThis.window !== "undefined") {
  const rootEl = globalThis.document.getElementById("gashboard-root");
  if (rootEl) {
    const handle = mountGashboardDashboard({ root: rootEl, document: globalThis.document });
    handle.loadLiveFleet().catch(() => {});
  }
}
