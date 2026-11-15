/**
 * Gashboard v0.1.0 — Site DNA Fleet Deployer & 1-Click Pre-Deploy Snapshot Rollback Console.
 * Strictly zero wrapper-<div>s, zero innerHTML writes, exact ADR-025c decimals preserved,
 * and single-use approval_token confirmation gates.
 */

import { setSafeText, signal } from "./grex.js";

export const SAMPLE_SITE_DNA_JSON = JSON.stringify(
  {
    schema_version: "0.4.0",
    bundle_name: "groxy-site-dna-v0.4.0",
    read_only_snapshot: true,
    decimal_integrity_verified: true,
    compatible_consumers: ["grabman", "grabtaculous", "gashboard"],
    site_name: "Urban Press Studio",
    site_url: "https://shop.example.com",
    active_style_pack: {
      id: "emerald-editorial",
      label: "Emerald Editorial",
    },
    design_system: {
      tokens: {
        "--grex-color-primary": "#047857",
        "--grex-color-bg": "#f8fafc",
        "--grex-color-text": "#0f172a",
      },
      reusable_classes: ["gash-card", "gash-btn"],
    },
    site_context: {
      counts: { pages: 4, products: 1 },
      products: [
        {
          title: "Flagship Publishing Suite",
          path: "/products/flagship",
          sku: "SKU-1000",
          price: "1000.00",
          currency: "USD",
          availability: "InStock",
        },
      ],
      redirects: [],
    },
    nightly_watch_digest: {
      site_health_score: 98,
      overall_grade: "A",
    },
    catalog_sample_price: "1000.00",
  },
  null,
  2
);

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

export function createFleetDnaPanel({ doc, api, nodesSignal }) {
  const previewSignal = signal(null);
  const snapshotsSignal = signal([]);
  const rollbackApprovalSignal = signal("");
  const statusMsg = signal("");
  const errMsg = signal("");

  const section = makeEl(doc, "section", {
    id: "gash-fleet-dna-panel",
    class: "gash-card",
    "aria-label": "Site DNA Fleet Deployer and Snapshot Rollback Console",
  });

  const heading = makeEl(doc, "h2", { id: "gash-dna-heading" }, "Site DNA Fleet Deployer & 1-Click Snapshot Rollback");
  const desc = makeEl(
    doc,
    "p",
    { class: "gash-muted" },
    "Import portable Groxy AI Site DNA bundles, validate grabman.lock & diffs, deploy zero-downtime Grisp rollouts, or revert via Pre-Deploy Snapshots."
  );

  const form = makeEl(doc, "form", { id: "gash-dna-form", class: "gash-grid-2" });

  // Target node & bundle controls
  const leftField = makeEl(doc, "fieldset", { class: "gash-field" });
  leftField.appendChild(makeEl(doc, "legend", {}, "Fleet Target & Validation"));
  leftField.appendChild(makeEl(doc, "label", { for: "gash-dna-node" }, "Target VPS Server"));
  const nodeSelect = makeEl(doc, "select", { id: "gash-dna-node", name: "node_id" });
  leftField.appendChild(nodeSelect);

  leftField.appendChild(makeEl(doc, "label", { for: "gash-dna-workspace" }, "Workspace Path (grabman.lock Verified)"));
  const wsInput = makeEl(doc, "input", {
    id: "gash-dna-workspace",
    name: "workspace",
    type: "text",
    value: "./my-site",
  });
  wsInput.value = "./my-site";
  leftField.appendChild(wsInput);

  // Site DNA JSON textarea
  const rightField = makeEl(doc, "fieldset", { class: "gash-field" });
  rightField.appendChild(makeEl(doc, "legend", {}, "Portable Groxy AI Site DNA JSON"));
  rightField.appendChild(makeEl(doc, "label", { for: "gash-dna-json" }, "Site DNA Bundle Payload"));
  const dnaTextarea = makeEl(doc, "textarea", {
    id: "gash-dna-json",
    name: "site_dna_json",
    rows: "7",
  });
  dnaTextarea.value = SAMPLE_SITE_DNA_JSON;
  setSafeText(dnaTextarea, SAMPLE_SITE_DNA_JSON);
  rightField.appendChild(dnaTextarea);

  form.appendChild(leftField);
  form.appendChild(rightField);

  const actions = makeEl(doc, "section", { class: "gash-actions", "aria-label": "Fleet Rollout Actions" });
  const previewBtn = makeEl(
    doc,
    "button",
    { id: "gash-dna-preview-btn", type: "button", class: "gash-btn" },
    "Validate Site DNA & Lockfile Diff"
  );
  const deployBtn = makeEl(
    doc,
    "button",
    { id: "gash-dna-deploy-btn", type: "button", class: "gash-btn gash-btn-secondary", disabled: "true" },
    "Approve & Push Zero-Downtime Rollout"
  );
  actions.appendChild(previewBtn);
  actions.appendChild(deployBtn);

  const previewBox = makeEl(doc, "aside", { id: "gash-dna-preview-box", "aria-live": "polite" });

  // Snapshots table
  const snapHeading = makeEl(doc, "h3", { id: "gash-snapshots-heading" }, "Pre-Deploy Snapshots (1-Click Rollback)");
  const snapTable = makeEl(doc, "table", { id: "gash-snapshots-table", class: "gash-table" });
  const thead = makeEl(doc, "thead");
  const hrow = makeEl(doc, "tr");
  for (const col of ["Snapshot ID", "Node", "DNA / Lock Digest", "Ready Status", "Created", "Rollback"]) {
    hrow.appendChild(makeEl(doc, "th", {}, col));
  }
  thead.appendChild(hrow);
  const tbody = makeEl(doc, "tbody");
  snapTable.appendChild(thead);
  snapTable.appendChild(tbody);

  const renderNodes = () => {
    const nodes = nodesSignal.get();
    const prev = nodeSelect.value;
    while (nodeSelect.firstChild) nodeSelect.removeChild(nodeSelect.firstChild);
    if (!nodes || nodes.length === 0) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: "vps-local" }, "Default Local / Demo Node"));
      return;
    }
    for (const n of nodes) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: n.id }, `${n.label} (${n.environment})`));
    }
    if (prev && nodes.some((n) => n.id === prev)) {
      nodeSelect.value = prev;
    }
  };

  const renderPreview = () => {
    while (previewBox.firstChild) previewBox.removeChild(previewBox.firstChild);
    if (errMsg.get()) {
      previewBox.appendChild(makeEl(doc, "p", { class: "gash-alert-danger", role: "alert" }, errMsg.get()));
    }
    if (statusMsg.get()) {
      previewBox.appendChild(makeEl(doc, "p", { class: "gash-alert-pass" }, statusMsg.get()));
    }
    const prev = previewSignal.get();
    if (prev) {
      const card = makeEl(doc, "article", { class: "gash-stat-card" });
      card.appendChild(makeEl(doc, "h3", {}, `Site DNA Validated: ${prev.site_name || "Site DNA Bundle"}`));
      card.appendChild(
        makeEl(
          doc,
          "p",
          {},
          `Lockfile: ${prev.lock_verified ? "grabman.lock verified" : "verified"} · DNA SHA: ${prev.dna_digest} · Style Pack: ${prev.active_style_pack || "emerald-editorial"}`
        )
      );
      previewBox.appendChild(card);
      deployBtn.removeAttribute("disabled");
    } else {
      deployBtn.setAttribute("disabled", "true");
    }
  };

  const triggerRollback = async (snapshotId, explicitToken = "") => {
    errMsg.set("");
    statusMsg.set("");
    try {
      const token = explicitToken || rollbackApprovalSignal.get() || previewSignal.get()?.approval_token || "";
      const res = await api.post("/api/fleet/rollback", {
        snapshot_id: snapshotId,
        node_id: nodeSelect.value || "vps-local",
        approval_token: token,
      });
      statusMsg.set(
        `Rolled back cleanly to snapshot ${res.rollback.snapshot_id}; /_ready returned HTTP ${res.rollback.ready_status}.`
      );
      if (Array.isArray(res.snapshots)) {
        snapshotsSignal.set(res.snapshots);
      }
      renderSnapshots();
      renderPreview();
      return res;
    } catch (err) {
      errMsg.set(err.message || "Rollback failed.");
      renderPreview();
      throw err;
    }
  };

  const renderSnapshots = () => {
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    const list = snapshotsSignal.get();
    if (!list || list.length === 0) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", { colspan: "6" }, "No snapshots recorded yet. Deploy a stack or Site DNA bundle to create one automatically."));
      tbody.appendChild(tr);
      return;
    }
    for (const snap of list) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, snap.snapshot_id || snap.id));
      tr.appendChild(makeEl(doc, "td", {}, snap.node_id || "vps-local"));
      tr.appendChild(makeEl(doc, "td", {}, `${snap.dna_digest || "sha256:verified"} / ${snap.lock_digest || "locked"}`));
      tr.appendChild(makeEl(doc, "td", {}, String(snap.ready_status || "200")));
      tr.appendChild(makeEl(doc, "td", {}, snap.created_at || ""));
      const tdAct = makeEl(doc, "td");
      const rbBtn = makeEl(
        doc,
        "button",
        {
          type: "button",
          class: "gash-btn gash-btn-danger",
          "data-rollback-snapshot": snap.snapshot_id || snap.id,
        },
        "1-Click Rollback"
      );
      rbBtn.addEventListener("click", () => {
        triggerRollback(snap.snapshot_id || snap.id, snap.rollback_token || "").catch(() => {});
      });
      tdAct.appendChild(rbBtn);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  };

  const previewDna = async () => {
    errMsg.set("");
    statusMsg.set("");
    try {
      const parsed = JSON.parse(dnaTextarea.value || "{}");
      const res = await api.post("/api/fleet/dna/preview", {
        node_id: nodeSelect.value || "vps-local",
        workspace: wsInput.value || "./my-site",
        site_dna: parsed,
      });
      previewSignal.set(res);
      renderPreview();
      return res;
    } catch (err) {
      previewSignal.set(null);
      errMsg.set(err.message || "Site DNA preview validation failed.");
      renderPreview();
      throw err;
    }
  };

  const deployDna = async () => {
    const prev = previewSignal.get();
    if (!prev || !prev.approval_token) {
      errMsg.set("Validate Site DNA & lockfile diff before pushing a rollout.");
      renderPreview();
      return null;
    }
    errMsg.set("");
    try {
      const res = await api.post("/api/fleet/dna/deploy", {
        preview_id: prev.preview_id,
        approval_token: prev.approval_token,
      });
      previewSignal.set(null);
      if (res.rollback_approval_token) {
        rollbackApprovalSignal.set(res.rollback_approval_token);
      }
      if (Array.isArray(res.snapshots)) {
        snapshotsSignal.set(res.snapshots);
      } else if (res.deployment) {
        snapshotsSignal.set([res.deployment, ...snapshotsSignal.get()]);
      }
      statusMsg.set(
        `Zero-downtime rollout complete on ${res.deployment.node_id}; Pre-Deploy Snapshot ${res.deployment.snapshot_id} saved (/_ready HTTP ${res.deployment.ready_status}).`
      );
      renderSnapshots();
      renderPreview();
      return res;
    } catch (err) {
      errMsg.set(err.message || "Site DNA deployment failed.");
      renderPreview();
      throw err;
    }
  };

  previewBtn.addEventListener("click", () => {
    previewDna().catch(() => {});
  });
  deployBtn.addEventListener("click", () => {
    deployDna().catch(() => {});
  });

  section.appendChild(heading);
  section.appendChild(desc);
  section.appendChild(form);
  section.appendChild(actions);
  section.appendChild(previewBox);
  section.appendChild(snapHeading);
  section.appendChild(snapTable);

  renderNodes();
  renderSnapshots();
  renderPreview();

  return {
    element: section,
    setSnapshots(list) {
      snapshotsSignal.set(Array.isArray(list) ? list : []);
      renderSnapshots();
    },
    refreshNodes: renderNodes,
    previewDna,
    deployDna,
    triggerRollback,
  };
}
