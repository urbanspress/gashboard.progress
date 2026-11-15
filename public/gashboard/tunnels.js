/**
 * Gashboard v0.1.0 — Encrypted 127.0.0.1 SSH Database Tunneling UI (Zero Wrapper-<div>).
 * Binds strictly to 127.0.0.1:<local_port> with max 8 concurrent tunnels and zero exposed secrets.
 */

import { setSafeText, signal } from "./grex.js";

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

export function formatSafeConnectionHint(tunnel) {
  const host = tunnel.local_host || "127.0.0.1";
  const port = tunnel.local_port || "5432";
  switch (String(tunnel.engine || "").toLowerCase()) {
    case "mariadb":
    case "mysql":
      return `mariadb --host=${host} --port=${port} --user=<db_user> <database>`;
    case "redis":
      return `redis-cli -h ${host} -p ${port}`;
    default:
      return `psql -h ${host} -p ${port} -U <db_user> <database>`;
  }
}

export function createTunnelsPanel({ doc, api, nodesSignal }) {
  const tunnelsSignal = signal([]);
  const statusMsg = signal("");
  const errMsg = signal("");

  const section = makeEl(doc, "section", {
    id: "gash-tunnels-panel",
    class: "gash-card",
    "aria-label": "Encrypted SSH Database Tunnels",
  });

  const heading = makeEl(doc, "h2", { id: "gash-tunnels-heading" }, "Encrypted SSH Database Tunnels (127.0.0.1 Loopback Only)");
  const desc = makeEl(
    doc,
    "p",
    { class: "gash-muted" },
    "Open private localhost tunnels (max 8 concurrent) to remote PostgreSQL, MariaDB, or Redis instances without exposing any database port publicly."
  );

  const form = makeEl(doc, "form", { id: "gash-tunnel-form", class: "gash-grid-4" });

  // Node selector
  const fNode = makeEl(doc, "section", { class: "gash-field" });
  fNode.appendChild(makeEl(doc, "label", { for: "gash-tun-node" }, "Target VPS Node"));
  const nodeSelect = makeEl(doc, "select", { id: "gash-tun-node", name: "node_id" });
  fNode.appendChild(nodeSelect);

  // Engine selector
  const fEngine = makeEl(doc, "section", { class: "gash-field" });
  fEngine.appendChild(makeEl(doc, "label", { for: "gash-tun-engine" }, "Database Engine"));
  const engineSelect = makeEl(doc, "select", { id: "gash-tun-engine", name: "engine" });
  engineSelect.appendChild(makeEl(doc, "option", { value: "postgres" }, "PostgreSQL (remote 127.0.0.1:5432)"));
  engineSelect.appendChild(makeEl(doc, "option", { value: "mariadb" }, "MariaDB (remote 127.0.0.1:3306)"));
  engineSelect.appendChild(makeEl(doc, "option", { value: "redis" }, "Redis (remote 127.0.0.1:6379)"));
  engineSelect.value = "postgres";
  fEngine.appendChild(engineSelect);

  // Local port
  const fPort = makeEl(doc, "section", { class: "gash-field" });
  fPort.appendChild(makeEl(doc, "label", { for: "gash-tun-port" }, "Local Loopback Port (0 = auto)"));
  const portInput = makeEl(doc, "input", {
    id: "gash-tun-port",
    name: "local_port",
    type: "text",
    value: "0",
  });
  portInput.value = "0";
  fPort.appendChild(portInput);

  // TTL
  const fTTL = makeEl(doc, "section", { class: "gash-field" });
  fTTL.appendChild(makeEl(doc, "label", { for: "gash-tun-ttl" }, "Session Timeout (Minutes)"));
  const ttlInput = makeEl(doc, "input", {
    id: "gash-tun-ttl",
    name: "ttl_minutes",
    type: "text",
    value: "60",
  });
  ttlInput.value = "60";
  fTTL.appendChild(ttlInput);

  form.appendChild(fNode);
  form.appendChild(fEngine);
  form.appendChild(fPort);
  form.appendChild(fTTL);

  const actions = makeEl(doc, "section", { class: "gash-actions", "aria-label": "Tunnel Controls" });
  const openBtn = makeEl(doc, "button", { id: "gash-tun-open-btn", type: "button", class: "gash-btn" }, "Open Secure DB Tunnel");
  const countBadge = makeEl(doc, "span", { id: "gash-tun-cap-badge", class: "gash-pill gash-pill-pass" }, "0 / 8 Active Tunnels");
  actions.appendChild(openBtn);
  actions.appendChild(countBadge);

  const feedback = makeEl(doc, "aside", { id: "gash-tun-feedback", "aria-live": "polite" });

  const table = makeEl(doc, "table", { id: "gash-tunnels-table", class: "gash-table" });
  const thead = makeEl(doc, "thead");
  const headRow = makeEl(doc, "tr");
  for (const label of ["Tunnel ID", "Node", "Engine", "Local Bind", "Safe CLI Command (No Secrets)", "Expires", "Action"]) {
    headRow.appendChild(makeEl(doc, "th", {}, label));
  }
  thead.appendChild(headRow);
  const tbody = makeEl(doc, "tbody");
  table.appendChild(thead);
  table.appendChild(tbody);

  const renderNodes = () => {
    const nodes = nodesSignal.get();
    const prev = nodeSelect.value;
    while (nodeSelect.firstChild) nodeSelect.removeChild(nodeSelect.firstChild);
    if (!nodes || nodes.length === 0) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: "vps-local" }, "Default Local / Demo Node"));
      return;
    }
    for (const n of nodes) {
      nodeSelect.appendChild(makeEl(doc, "option", { value: n.id }, `${n.label} (${n.host})`));
    }
    if (prev && nodes.some((n) => n.id === prev)) {
      nodeSelect.value = prev;
    }
  };

  const renderFeedback = () => {
    while (feedback.firstChild) feedback.removeChild(feedback.firstChild);
    if (errMsg.get()) {
      feedback.appendChild(makeEl(doc, "p", { class: "gash-alert-danger", role: "alert" }, errMsg.get()));
    }
    if (statusMsg.get()) {
      feedback.appendChild(makeEl(doc, "p", { class: "gash-alert-pass" }, statusMsg.get()));
    }
  };

  const closeTunnel = async (tunnelId) => {
    errMsg.set("");
    try {
      await api.post("/api/tunnels/close", { id: tunnelId });
      tunnelsSignal.set(tunnelsSignal.get().filter((t) => t.id !== tunnelId));
      statusMsg.set(`Closed 127.0.0.1 SSH tunnel ${tunnelId}.`);
      renderTable();
      renderFeedback();
    } catch (err) {
      errMsg.set(err.message || "Failed to close tunnel.");
      renderFeedback();
    }
  };

  const renderTable = () => {
    const items = tunnelsSignal.get();
    setSafeText(countBadge, `${items.length} / 8 Active Tunnels`);
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    if (items.length === 0) {
      const tr = makeEl(doc, "tr");
      const td = makeEl(doc, "td", { colspan: "7" }, "No active SSH database tunnels. Click \"Open Secure DB Tunnel\" above.");
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    for (const tun of items) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, tun.id));
      tr.appendChild(makeEl(doc, "td", {}, tun.node_id));
      tr.appendChild(makeEl(doc, "td", {}, tun.engine));
      tr.appendChild(makeEl(doc, "td", {}, `${tun.local_host}:${tun.local_port}`));
      tr.appendChild(makeEl(doc, "td", {}, formatSafeConnectionHint(tun)));
      tr.appendChild(makeEl(doc, "td", {}, tun.expires_at || ""));
      const tdAct = makeEl(doc, "td");
      const closeBtn = makeEl(
        doc,
        "button",
        { type: "button", class: "gash-btn gash-btn-danger", "data-close-tunnel": tun.id },
        "Close Tunnel"
      );
      closeBtn.addEventListener("click", () => {
        closeTunnel(tun.id).catch(() => {});
      });
      tdAct.appendChild(closeBtn);
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    }
  };

  const openTunnel = async () => {
    errMsg.set("");
    statusMsg.set("");
    try {
      const res = await api.post("/api/tunnels/open", {
        node_id: nodeSelect.value || "vps-local",
        engine: engineSelect.value || "postgres",
        local_port: String(portInput.value || "0").trim(),
        ttl_minutes: String(ttlInput.value || "60").trim(),
      });
      tunnelsSignal.set([...tunnelsSignal.get(), res.tunnel]);
      statusMsg.set(
        `Opened encrypted 127.0.0.1:${res.tunnel.local_port} tunnel to ${res.tunnel.engine} (${res.tunnel.id}).`
      );
      renderTable();
      renderFeedback();
      return res;
    } catch (err) {
      errMsg.set(err.message || "Failed to open SSH DB tunnel.");
      renderFeedback();
      throw err;
    }
  };

  openBtn.addEventListener("click", () => {
    openTunnel().catch(() => {});
  });

  section.appendChild(heading);
  section.appendChild(desc);
  section.appendChild(form);
  section.appendChild(actions);
  section.appendChild(feedback);
  section.appendChild(table);

  renderNodes();
  renderTable();

  return {
    element: section,
    setTunnels(list) {
      tunnelsSignal.set(Array.isArray(list) ? list : []);
      renderTable();
    },
    refreshNodes: renderNodes,
    openTunnel,
    closeTunnel,
    getTunnels: () => tunnelsSignal.get(),
  };
}
