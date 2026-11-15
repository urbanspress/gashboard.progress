/**
 * Gashboard v0.1.0 — 1-Click App Marketplace Frontend (Zero Wrapper-<div> Pure Grex JS).
 * Features GrabLab CMS v1.0.1 + Grex Theme Builder v1.0.0 + Groxy AI v1.0.0 alongside
 * companion self-hosted stacks, edge proxy choices, and single-use approval_token deploy gates.
 */

import { setSafeText, signal } from "./grex.js";

export const DEFAULT_MARKETPLACE_CATALOG = Object.freeze([
  {
    id: "grablab-grex-bundle",
    name: "GrabLab CMS + Grex Theme Builder + Groxy AI",
    category: "flagship",
    version: "1.0.1",
    read_only_hardened: true,
    summary: "Complete zero-plugin CMS, visual studio, and autonomous SEO agent in hardened --read-only containers.",
  },
  {
    id: "grablab-full-stack",
    name: "GrabLab CMS Stack + Private PostgreSQL 18",
    category: "enterprise",
    version: "1.0.1",
    read_only_hardened: true,
    summary: "Full publishing stack backed by a loopback-only PostgreSQL 18 store.",
  },
  {
    id: "grab-grisp-app",
    name: "Standalone GRAB v1.1.0 Grisp Worker App",
    category: "core",
    version: "1.1.0",
    read_only_hardened: true,
    summary: "High-speed custom .grab application with multi-worker Grisp supervisor.",
  },
  {
    id: "postgres-18",
    name: "PostgreSQL 18 (127.0.0.1 Loopback Only)",
    category: "datastore",
    version: "18.1",
    read_only_hardened: true,
    summary: "Private PostgreSQL instance reachable exclusively via encrypted Gashboard SSH tunnels.",
  },
  {
    id: "mariadb-11-8",
    name: "MariaDB 11.8 (127.0.0.1 Loopback Only)",
    category: "datastore",
    version: "11.8",
    read_only_hardened: true,
    summary: "Private relational database reachable exclusively over SSH tunnels.",
  },
  {
    id: "redis-standalone",
    name: "Redis Standalone Cache (127.0.0.1 Loopback Only)",
    category: "datastore",
    version: "7.4",
    read_only_hardened: true,
    summary: "Private in-memory cache and rate limiter with zero public ports.",
  },
  {
    id: "analytics",
    name: "Privacy-First Web Analytics (Plausible)",
    category: "companion",
    version: "2.1",
    read_only_hardened: true,
    summary: "Cookie-free analytics behind automatic HTTPS.",
  },
  {
    id: "object-storage",
    name: "Garage S3 Media & Backup Storage",
    category: "companion",
    version: "1.0",
    read_only_hardened: true,
    summary: "Self-hosted S3-compatible object storage for uploads and snapshots.",
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

export function createMarketplacePanel({ doc, api, nodesSignal, onDeploymentComplete }) {
  const catalogSignal = signal([...DEFAULT_MARKETPLACE_CATALOG]);
  const selectedBlueprint = signal(DEFAULT_MARKETPLACE_CATALOG[0].id);
  const planPreview = signal(null);
  const statusMessage = signal("");
  const errorMessage = signal("");

  const section = makeEl(doc, "section", {
    id: "gash-marketplace-panel",
    class: "gash-card",
    "aria-label": "1-Click App Marketplace",
  });

  const heading = makeEl(doc, "h2", { id: "gash-marketplace-heading" }, "1-Click App Marketplace (Hardened --read-only)");
  const subtitle = makeEl(
    doc,
    "p",
    { class: "gash-muted" },
    "Deploy GrabLab CMS + Grex Theme Builder + Groxy AI or private companion services with automatic Caddy, Nginx, or Cloudflare Tunnel SSL."
  );

  const form = makeEl(doc, "form", { id: "gash-marketplace-form", class: "gash-grid-2" });

  // Blueprint field
  const bpWrap = makeEl(doc, "fieldset", { class: "gash-field" });
  bpWrap.appendChild(makeEl(doc, "legend", {}, "Stack Selection"));
  bpWrap.appendChild(makeEl(doc, "label", { for: "gash-mp-blueprint" }, "Application Blueprint"));
  const bpSelect = makeEl(doc, "select", { id: "gash-mp-blueprint", name: "blueprint_id" });
  const renderBlueprintOptions = () => {
    while (bpSelect.firstChild) bpSelect.removeChild(bpSelect.firstChild);
    for (const item of catalogSignal.get()) {
      bpSelect.appendChild(makeEl(doc, "option", { value: item.id }, `${item.name} (v${item.version})`));
    }
    bpSelect.value = selectedBlueprint.get();
  };
  renderBlueprintOptions();
  bpSelect.addEventListener("change", () => selectedBlueprint.set(bpSelect.value));
  bpWrap.appendChild(bpSelect);

  bpWrap.appendChild(makeEl(doc, "label", { for: "gash-mp-node" }, "Target VPS Server"));
  const nodeSelect = makeEl(doc, "select", { id: "gash-mp-node", name: "node_id" });
  bpWrap.appendChild(nodeSelect);

  // Domain & Edge Proxy field
  const edgeWrap = makeEl(doc, "fieldset", { class: "gash-field" });
  edgeWrap.appendChild(makeEl(doc, "legend", {}, "Domain & Edge SSL"));
  edgeWrap.appendChild(makeEl(doc, "label", { for: "gash-mp-appname" }, "App Name"));
  const appInput = makeEl(doc, "input", {
    id: "gash-mp-appname",
    name: "app_name",
    type: "text",
    value: "my-storefront",
    placeholder: "my-storefront",
  });
  appInput.value = "my-storefront";
  edgeWrap.appendChild(appInput);

  edgeWrap.appendChild(makeEl(doc, "label", { for: "gash-mp-domain" }, "Public HTTPS Domain"));
  const domainInput = makeEl(doc, "input", {
    id: "gash-mp-domain",
    name: "domain",
    type: "text",
    value: "shop.example.com",
    placeholder: "shop.example.com",
  });
  domainInput.value = "shop.example.com";
  edgeWrap.appendChild(domainInput);

  edgeWrap.appendChild(makeEl(doc, "label", { for: "gash-mp-proxy" }, "Edge HTTPS Proxy"));
  const proxySelect = makeEl(doc, "select", { id: "gash-mp-proxy", name: "edge_proxy" });
  proxySelect.appendChild(makeEl(doc, "option", { value: "caddy" }, "Caddy Automatic HTTPS (Recommended)"));
  proxySelect.appendChild(makeEl(doc, "option", { value: "nginx" }, "Nginx + Certbot"));
  proxySelect.appendChild(makeEl(doc, "option", { value: "cloudflare-tunnel" }, "Cloudflare Tunnel (Zero Open Ports)"));
  proxySelect.value = "caddy";
  edgeWrap.appendChild(proxySelect);

  form.appendChild(bpWrap);
  form.appendChild(edgeWrap);

  const actions = makeEl(doc, "section", { class: "gash-actions", "aria-label": "Marketplace Actions" });
  const planBtn = makeEl(doc, "button", { id: "gash-mp-plan-btn", type: "button", class: "gash-btn" }, "Preview Security & Preflight Plan");
  const deployBtn = makeEl(
    doc,
    "button",
    { id: "gash-mp-deploy-btn", type: "button", class: "gash-btn gash-btn-secondary", disabled: "true" },
    "Approve & Deploy 1-Click Stack"
  );
  actions.appendChild(planBtn);
  actions.appendChild(deployBtn);

  const reviewBox = makeEl(doc, "aside", { id: "gash-mp-review", "aria-live": "polite" });

  const renderNodes = () => {
    const nodes = nodesSignal.get();
    const prev = nodeSelect.value;
    while (nodeSelect.firstChild) nodeSelect.removeChild(nodeSelect.firstChild);
    if (!nodes || nodes.length === 0) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: "vps-local" }, "Default Local / Demo Node"));
      return;
    }
    for (const n of nodes) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: n.id }, `${n.label} (${n.host}) [${n.environment}]`));
    }
    if (prev && nodes.some((n) => n.id === prev)) {
      nodeSelect.value = prev;
    }
  };

  const renderReview = () => {
    while (reviewBox.firstChild) reviewBox.removeChild(reviewBox.firstChild);
    const err = errorMessage.get();
    if (err) {
      reviewBox.appendChild(makeEl(doc, "p", { class: "gash-alert-danger", role: "alert" }, err));
    }
    const msg = statusMessage.get();
    if (msg) {
      reviewBox.appendChild(makeEl(doc, "p", { class: "gash-alert-pass" }, msg));
    }
    const plan = planPreview.get();
    if (plan) {
      const card = makeEl(doc, "article", { class: "gash-stat-card" });
      card.appendChild(makeEl(doc, "h3", {}, `Pre-Deploy Safety Review: ${plan.blueprint_id}`));
      card.appendChild(
        makeEl(
          doc,
          "p",
          {},
          `Preflight: grabman doctor=${plan.doctor_status || "pass"} · Hardening: read_only=${String(plan.read_only)} · Edge SSL=${plan.edge_proxy} (${plan.domain})`
        )
      );
      card.appendChild(
        makeEl(doc, "p", { class: "gash-code-line" }, `Single-use approval_token minted (expires once consumed)`)
      );
      reviewBox.appendChild(card);
      deployBtn.removeAttribute("disabled");
    } else {
      deployBtn.setAttribute("disabled", "true");
    }
  };

  const runPlan = async () => {
    errorMessage.set("");
    statusMessage.set("");
    try {
      const res = await api.post("/api/marketplace/plan", {
        node_id: nodeSelect.value || "vps-local",
        blueprint_id: bpSelect.value,
        app_name: appInput.value || "my-storefront",
        domain: domainInput.value || "shop.example.com",
        edge_proxy: proxySelect.value || "caddy",
      });
      planPreview.set(res);
      renderReview();
      return res;
    } catch (err) {
      planPreview.set(null);
      errorMessage.set(err.message || "Marketplace preflight failed.");
      renderReview();
      throw err;
    }
  };

  const runDeploy = async () => {
    const plan = planPreview.get();
    if (!plan || !plan.approval_token) {
      errorMessage.set("Generate a pre-deploy plan before approving deployment.");
      renderReview();
      return null;
    }
    errorMessage.set("");
    try {
      const res = await api.post("/api/marketplace/deploy", {
        plan_id: plan.plan_id,
        approval_token: plan.approval_token,
      });
      planPreview.set(null);
      statusMessage.set(
        `Deployed ${res.install.blueprint_id} to ${res.install.domain} (${res.install.edge_proxy}) with Pre-Deploy Snapshot ${res.install.snapshot_id}.`
      );
      renderReview();
      if (typeof onDeploymentComplete === "function") {
        onDeploymentComplete(res);
      }
      return res;
    } catch (err) {
      errorMessage.set(err.message || "Marketplace deployment failed.");
      renderReview();
      throw err;
    }
  };

  planBtn.addEventListener("click", () => {
    runPlan().catch(() => {});
  });
  deployBtn.addEventListener("click", () => {
    runDeploy().catch(() => {});
  });

  section.appendChild(heading);
  section.appendChild(subtitle);
  section.appendChild(form);
  section.appendChild(actions);
  section.appendChild(reviewBox);

  renderNodes();
  renderReview();

  return {
    element: section,
    setCatalog(items) {
      if (Array.isArray(items) && items.length > 0) {
        catalogSignal.set(items);
        renderBlueprintOptions();
      }
    },
    refreshNodes: renderNodes,
    runPlan,
    runDeploy,
  };
}
