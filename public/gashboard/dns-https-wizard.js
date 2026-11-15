/**
 * Gashboard v0.3.0 — Namecheap Encrypted Vault, Email-Safe DNS Provisioner,
 * Live Propagation Preflight & Grabtaculous Auto-HTTPS + 1-Click Rollback Wizard.
 * Strictly zero wrapper-<div>s, zero innerHTML writes, zero plaintext secret storage in DOM.
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

function clearChildren(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

export function formatVaultStatusText(st) {
  if (!st || !st.configured) {
    return "Vault status: Not configured yet. Credentials are encrypted with AES-256-GCM before storage.";
  }
  const envLabel = st.sandbox ? "Sandbox" : "Production";
  const cipher = st.vault_cipher || "AES-256-GCM";
  return `Configured (${envLabel} · ${cipher}) · User: ${st.api_user_masked || "***"} · Client IP: ${st.client_ip_masked || st.client_ip || "***"}`;
}

export function createDnsHttpsWizardPanel({ doc, api, nodesSignal }) {
  const vaultSignal = signal(null);
  const dnsPlanSignal = signal(null);
  const dnsApprovalSignal = signal("");
  const lastDnsSnapIdSignal = signal("");
  const lastDnsRollbackTokSignal = signal("");
  const propSignal = signal(null);
  const httpsPlanSignal = signal(null);
  const httpsApprovalSignal = signal("");
  const dnsSnapshotsSignal = signal([]);
  const httpsRolloutsSignal = signal([]);
  const statusSignal = signal("");
  const errorSignal = signal("");

  const section = makeEl(doc, "section", {
    id: "gashboard-dns-https-wizard",
    class: "gash-card",
    "aria-label": "Namecheap DNS and Auto-HTTPS Wizard",
  });

  const heading = makeEl(doc, "h2", { id: "gash-dns-heading" }, "Namecheap DNS & Auto-HTTPS Wizard");
  const lead = makeEl(
    doc,
    "p",
    { class: "gash-muted" },
    "Store Namecheap credentials encrypted with AES-256-GCM, update domain records while keeping MX/SPF/DKIM email intact, block ACME issuance until DNS propagates, and roll back cleanly in 1 click."
  );

  const alertBox = makeEl(doc, "p", { id: "gash-dns-wizard-alert", role: "status", "aria-live": "polite" });
  alertBox.setAttribute("hidden", "hidden");

  function setAlert(kind, msg) {
    if (kind === "error") {
      errorSignal.set(msg);
      statusSignal.set("");
      alertBox.setAttribute("class", "gash-alert-danger");
      alertBox.setAttribute("role", "alert");
      alertBox.removeAttribute("hidden");
      setSafeText(alertBox, msg);
      return;
    }
    if (kind === "pass") {
      errorSignal.set("");
      statusSignal.set(msg);
      alertBox.setAttribute("class", "gash-alert-pass");
      alertBox.setAttribute("role", "status");
      alertBox.removeAttribute("hidden");
      setSafeText(alertBox, msg);
      return;
    }
    errorSignal.set("");
    statusSignal.set("");
    alertBox.setAttribute("hidden", "hidden");
    setSafeText(alertBox, "");
  }

  // Step 1: Encrypted Namecheap Vault
  const vaultCard = makeEl(doc, "article", { class: "gash-stat-card", "aria-label": "Step 1: Encrypted Namecheap Credential Vault" });
  const vaultHeading = makeEl(doc, "h3", {}, "Step 1 · Encrypted Namecheap Credential Vault");
  const vaultStatusP = makeEl(doc, "p", { id: "gash-nc-vault-status", class: "gash-code-line" }, formatVaultStatusText(null));

  const vaultForm = makeEl(doc, "form", { id: "gash-dns-vault-form", class: "gash-grid-4" });
  const fUser = makeEl(doc, "p", { class: "gash-field" });
  const lUser = makeEl(doc, "label", { for: "gash-nc-api-user" }, "Namecheap API User");
  const inUser = makeEl(doc, "input", { id: "gash-nc-api-user", type: "text", autocomplete: "off", placeholder: "your-nc-user" });
  fUser.appendChild(lUser);
  fUser.appendChild(inUser);

  const fKey = makeEl(doc, "p", { class: "gash-field" });
  const lKey = makeEl(doc, "label", { for: "gash-nc-api-key" }, "Namecheap API Key (Write-Only Vault)");
  const inKey = makeEl(doc, "input", { id: "gash-nc-api-key", type: "password", autocomplete: "off", placeholder: "never echoed after save" });
  fKey.appendChild(lKey);
  fKey.appendChild(inKey);

  const fClientIp = makeEl(doc, "p", { class: "gash-field" });
  const lClientIp = makeEl(doc, "label", { for: "gash-nc-client-ip" }, "Whitelisted Client IPv4");
  const inClientIp = makeEl(doc, "input", { id: "gash-nc-client-ip", type: "text", autocomplete: "off", placeholder: "203.0.113.5" });
  fClientIp.appendChild(lClientIp);
  fClientIp.appendChild(inClientIp);

  const fSandbox = makeEl(doc, "p", { class: "gash-field" });
  const lSandbox = makeEl(doc, "label", { for: "gash-nc-sandbox" }, "Namecheap Environment");
  const selSandbox = makeEl(doc, "select", { id: "gash-nc-sandbox" });
  selSandbox.appendChild(makeEl(doc, "option", { value: "true" }, "Sandbox (Safe Test)"));
  selSandbox.appendChild(makeEl(doc, "option", { value: "false" }, "Production API"));
  fSandbox.appendChild(lSandbox);
  fSandbox.appendChild(selSandbox);

  vaultForm.appendChild(fUser);
  vaultForm.appendChild(fKey);
  vaultForm.appendChild(fClientIp);
  vaultForm.appendChild(fSandbox);

  const vaultActions = makeEl(doc, "p", { class: "gash-actions" });
  const saveVaultBtn = makeEl(doc, "button", { id: "gash-nc-save-btn", type: "submit", class: "gash-btn" }, "Save Encrypted Vault Credentials");
  vaultActions.appendChild(saveVaultBtn);
  vaultForm.appendChild(vaultActions);

  vaultCard.appendChild(vaultHeading);
  vaultCard.appendChild(vaultStatusP);
  vaultCard.appendChild(vaultForm);

  // Step 2: Email-Safe DNS Diff & Provisioner
  const dnsCard = makeEl(doc, "article", { class: "gash-stat-card", "aria-label": "Step 2: Email-Safe DNS Provisioner" });
  const dnsHeading = makeEl(doc, "h3", {}, "Step 2 · Email-Safe DNS Record Preview & Apply");
  const dnsForm = makeEl(doc, "form", { id: "gash-dns-plan-form", class: "gash-grid-4" });

  const fNode = makeEl(doc, "p", { class: "gash-field" });
  const lNode = makeEl(doc, "label", { for: "gash-dns-node" }, "Target VPS Node");
  const selNode = makeEl(doc, "select", { id: "gash-dns-node" });
  fNode.appendChild(lNode);
  fNode.appendChild(selNode);

  const fDomain = makeEl(doc, "p", { class: "gash-field" });
  const lDomain = makeEl(doc, "label", { for: "gash-dns-domain" }, "Domain Name");
  const inDomain = makeEl(doc, "input", { id: "gash-dns-domain", type: "text", value: "example.com" });
  fDomain.appendChild(lDomain);
  fDomain.appendChild(inDomain);

  const fSub = makeEl(doc, "p", { class: "gash-field" });
  const lSub = makeEl(doc, "label", { for: "gash-dns-subdomain" }, "Host / Subdomain (@ or prefix)");
  const inSub = makeEl(doc, "input", { id: "gash-dns-subdomain", type: "text", value: "@" });
  fSub.appendChild(lSub);
  fSub.appendChild(inSub);

  const fTargetIp = makeEl(doc, "p", { class: "gash-field" });
  const lTargetIp = makeEl(doc, "label", { for: "gash-dns-target-ip" }, "Target VPS IPv4");
  const inTargetIp = makeEl(doc, "input", { id: "gash-dns-target-ip", type: "text", placeholder: "198.51.100.24" });
  fTargetIp.appendChild(lTargetIp);
  fTargetIp.appendChild(inTargetIp);

  const fTtl = makeEl(doc, "p", { class: "gash-field" });
  const lTtl = makeEl(doc, "label", { for: "gash-dns-ttl" }, "Record TTL (seconds)");
  const inTtl = makeEl(doc, "input", { id: "gash-dns-ttl", type: "text", value: "300" });
  fTtl.appendChild(lTtl);
  fTtl.appendChild(inTtl);

  const fEdge = makeEl(doc, "p", { class: "gash-field" });
  const lEdge = makeEl(doc, "label", { for: "gash-dns-edge-proxy" }, "Edge HTTPS Mode");
  const selEdge = makeEl(doc, "select", { id: "gash-dns-edge-proxy" });
  selEdge.appendChild(makeEl(doc, "option", { value: "caddy" }, "Caddy Auto-HTTPS (Let's Encrypt)"));
  selEdge.appendChild(makeEl(doc, "option", { value: "nginx" }, "Nginx + Certbot"));
  selEdge.appendChild(makeEl(doc, "option", { value: "cloudflare-tunnel" }, "Cloudflare Tunnel (Zero Public Port)"));
  fEdge.appendChild(lEdge);
  fEdge.appendChild(selEdge);

  dnsForm.appendChild(fNode);
  dnsForm.appendChild(fDomain);
  dnsForm.appendChild(fSub);
  dnsForm.appendChild(fTargetIp);
  dnsForm.appendChild(fTtl);
  dnsForm.appendChild(fEdge);

  const dnsActions = makeEl(doc, "p", { class: "gash-actions" });
  const planDnsBtn = makeEl(doc, "button", { id: "gash-dns-plan-btn", type: "submit", class: "gash-btn" }, "Preview Email-Safe DNS Changes");
  const applyDnsBtn = makeEl(doc, "button", { id: "gash-dns-apply-btn", type: "button", class: "gash-btn gash-btn-secondary", disabled: "disabled" }, "Approve & Apply DNS Records");
  dnsActions.appendChild(planDnsBtn);
  dnsActions.appendChild(applyDnsBtn);
  dnsForm.appendChild(dnsActions);

  const diffSummaryP = makeEl(doc, "p", { id: "gash-dns-diff-summary", class: "gash-muted" }, "Run a DNS preview to inspect changes. Existing MX, TXT, SPF, and DKIM email records are never removed.");
  const diffScroll = makeEl(doc, "section", { class: "gash-table-scroll", "aria-label": "DNS Diff Preview Table" });
  const diffTable = makeEl(doc, "table", { id: "gash-dns-diff-table", class: "gash-table" });
  const diffHead = makeEl(doc, "thead");
  const diffHeadRow = makeEl(doc, "tr");
  for (const hLabel of ["Action", "Host", "Type", "Current", "Next", "Notes"]) {
    diffHeadRow.appendChild(makeEl(doc, "th", { scope: "col" }, hLabel));
  }
  diffHead.appendChild(diffHeadRow);
  const diffBody = makeEl(doc, "tbody");
  diffTable.appendChild(diffHead);
  diffTable.appendChild(diffBody);
  diffScroll.appendChild(diffTable);

  dnsCard.appendChild(dnsHeading);
  dnsCard.appendChild(dnsForm);
  dnsCard.appendChild(diffSummaryP);
  dnsCard.appendChild(diffScroll);

  // Step 3 & Step 4: Propagation Preflight & Grabtaculous Auto-HTTPS + Rollback
  const httpsCard = makeEl(doc, "article", { class: "gash-stat-card", "aria-label": "Step 3 and 4: DNS Propagation Guard and Auto-HTTPS" });
  const httpsHeading = makeEl(doc, "h3", {}, "Step 3 & 4 · Live Propagation Guard, Auto-HTTPS & Rollback");
  const propStatusP = makeEl(doc, "p", { id: "gash-dns-prop-status", class: "gash-code-line", "aria-live": "polite" }, "Propagation check pending: certificate issuance is blocked until DNS resolves cleanly to your target VPS IP.");

  const httpsGrid = makeEl(doc, "section", { class: "gash-grid-2", "aria-label": "Auto-HTTPS Rollout Settings" });
  const fWorkspace = makeEl(doc, "p", { class: "gash-field" });
  const lWorkspace = makeEl(doc, "label", { for: "gash-https-workspace" }, "Remote Site Workspace");
  const inWorkspace = makeEl(doc, "input", { id: "gash-https-workspace", type: "text", value: "./site" });
  fWorkspace.appendChild(lWorkspace);
  fWorkspace.appendChild(inWorkspace);

  const fBlueprint = makeEl(doc, "p", { class: "gash-field" });
  const lBlueprint = makeEl(doc, "label", { for: "gash-https-blueprint" }, "Edge Stack Blueprint");
  const selBlueprint = makeEl(doc, "select", { id: "gash-https-blueprint" });
  selBlueprint.appendChild(makeEl(doc, "option", { value: "grab-grisp-app" }, "GRAB Grisp App Edge Config"));
  selBlueprint.appendChild(makeEl(doc, "option", { value: "grablab-grex-bundle" }, "GrabLab CMS + Grex Builder Stack"));
  selBlueprint.appendChild(makeEl(doc, "option", { value: "grablab-full-stack" }, "GrabLab Full Stack + PostgreSQL 18"));
  fBlueprint.appendChild(lBlueprint);
  fBlueprint.appendChild(selBlueprint);

  httpsGrid.appendChild(fWorkspace);
  httpsGrid.appendChild(fBlueprint);

  const httpsActions = makeEl(doc, "p", { class: "gash-actions" });
  const checkPropBtn = makeEl(doc, "button", { id: "gash-dns-prop-btn", type: "button", class: "gash-btn gash-btn-secondary" }, "Check Live DNS Propagation");
  const planHttpsBtn = makeEl(doc, "button", { id: "gash-https-plan-btn", type: "button", class: "gash-btn" }, "Preflight Propagation & Plan HTTPS");
  const applyHttpsBtn = makeEl(doc, "button", { id: "gash-https-apply-btn", type: "button", class: "gash-btn gash-btn-secondary", disabled: "disabled" }, "Provision Auto-HTTPS & Verify /_ready");
  httpsActions.appendChild(checkPropBtn);
  httpsActions.appendChild(planHttpsBtn);
  httpsActions.appendChild(applyHttpsBtn);

  const rolloutsHeading = makeEl(doc, "h4", {}, "DNS Snapshots & Auto-HTTPS Rollouts (1-Click Rollback)");
  const rolloutScroll = makeEl(doc, "section", { class: "gash-table-scroll", "aria-label": "DNS and HTTPS Rollback History" });
  const rolloutTable = makeEl(doc, "table", { id: "gash-dns-rollouts-table", class: "gash-table" });
  const rHead = makeEl(doc, "thead");
  const rHeadRow = makeEl(doc, "tr");
  for (const label of ["Type", "Domain", "Mode / Target", "Status", "Action"]) {
    rHeadRow.appendChild(makeEl(doc, "th", { scope: "col" }, label));
  }
  rHead.appendChild(rHeadRow);
  const rolloutBody = makeEl(doc, "tbody");
  rolloutTable.appendChild(rHead);
  rolloutTable.appendChild(rolloutBody);
  rolloutScroll.appendChild(rolloutTable);

  httpsCard.appendChild(httpsHeading);
  httpsCard.appendChild(propStatusP);
  httpsCard.appendChild(httpsGrid);
  httpsCard.appendChild(httpsActions);
  httpsCard.appendChild(rolloutsHeading);
  httpsCard.appendChild(rolloutScroll);

  section.appendChild(heading);
  section.appendChild(lead);
  section.appendChild(alertBox);
  section.appendChild(vaultCard);
  section.appendChild(dnsCard);
  section.appendChild(httpsCard);

  function renderDiffs(planData) {
    clearChildren(diffBody);
    if (!planData || !Array.isArray(planData.diffs)) {
      return;
    }
    setSafeText(diffSummaryP, planData.plain_summary || `Preserved ${planData.preserved_email_count || "0"} email records.`);
    for (const d of planData.diffs) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, String(d.action || "")));
      tr.appendChild(makeEl(doc, "td", {}, String(d.name || "")));
      tr.appendChild(makeEl(doc, "td", {}, String(d.type || "")));
      tr.appendChild(makeEl(doc, "td", {}, String(d.previous_address || "—")));
      tr.appendChild(makeEl(doc, "td", {}, String(d.next_address || "—")));
      tr.appendChild(makeEl(doc, "td", {}, String(d.reason || "")));
      diffBody.appendChild(tr);
    }
  }

  function renderHistory() {
    clearChildren(rolloutBody);
    const dnsSnaps = dnsSnapshotsSignal.get();
    const httpsRolls = httpsRolloutsSignal.get();

    for (const r of httpsRolls) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, "Auto-HTTPS"));
      tr.appendChild(makeEl(doc, "td", {}, String(r.domain || "")));
      tr.appendChild(makeEl(doc, "td", {}, `${r.edge_proxy || ""} (/ready ${r.ready_status || "200"})`));
      tr.appendChild(makeEl(doc, "td", {}, String(r.status || "")));
      const tdAct = makeEl(doc, "td");
      if (r.status === "active" && r.rollback_token) {
        const rbBtn = makeEl(
          doc,
          "button",
          {
            type: "button",
            class: "gash-btn gash-btn-danger",
            "data-https-rollback-id": String(r.id),
          },
          "1-Click Edge + DNS Rollback"
        );
        rbBtn.addEventListener("click", () => {
          rollbackHttps(r.id, r.rollback_token).catch(() => {});
        });
        tdAct.appendChild(rbBtn);
      } else {
        tdAct.appendChild(makeEl(doc, "span", { class: "gash-muted" }, r.status === "rolled_back" ? "Rolled back" : "Saved"));
      }
      tr.appendChild(tdAct);
      rolloutBody.appendChild(tr);
    }

    for (const s of dnsSnaps) {
      const tr = makeEl(doc, "tr");
      tr.appendChild(makeEl(doc, "td", {}, "DNS Snapshot"));
      tr.appendChild(makeEl(doc, "td", {}, `${s.domain || ""} (${s.subdomain || "@"})`));
      tr.appendChild(makeEl(doc, "td", {}, `${s.target_ip || ""} · ${s.preserved_email_count || "0"} email kept`));
      tr.appendChild(makeEl(doc, "td", {}, String(s.status || "")));
      const tdAct = makeEl(doc, "td");
      if (s.status === "applied" && s.rollback_token) {
        const rbBtn = makeEl(
          doc,
          "button",
          {
            type: "button",
            class: "gash-btn gash-btn-danger",
            "data-dns-rollback-id": String(s.id),
          },
          "Restore Prior DNS"
        );
        rbBtn.addEventListener("click", () => {
          rollbackDns(s.id, s.rollback_token).catch(() => {});
        });
        tdAct.appendChild(rbBtn);
      } else {
        tdAct.appendChild(makeEl(doc, "span", { class: "gash-muted" }, s.status === "rolled_back" ? "Restored" : "Recorded"));
      }
      tr.appendChild(tdAct);
      rolloutBody.appendChild(tr);
    }
  }

  function refreshNodes() {
    const nodes = nodesSignal ? nodesSignal.get() : [];
    const currentVal = selNode.value;
    clearChildren(selNode);
    for (const n of nodes) {
      const opt = makeEl(doc, "option", { value: n.id }, `${n.label} (${n.host})`);
      selNode.appendChild(opt);
    }
    if (currentVal && nodes.some((n) => n.id === currentVal)) {
      selNode.value = currentVal;
    } else if (nodes.length > 0) {
      selNode.value = nodes[0].id;
    }
    const chosen = nodes.find((n) => n.id === selNode.value) || nodes[0];
    if (chosen) {
      if (!inTargetIp.value) {
        inTargetIp.value = chosen.host || "";
      }
      if (!inDomain.value || inDomain.value === "example.com") {
        if (chosen.domain) {
          inDomain.value = chosen.domain;
        }
      }
    }
  }

  selNode.addEventListener("change", () => {
    const nodes = nodesSignal ? nodesSignal.get() : [];
    const chosen = nodes.find((n) => n.id === selNode.value);
    if (chosen) {
      inTargetIp.value = chosen.host || inTargetIp.value;
      if (chosen.domain) {
        inDomain.value = chosen.domain;
      }
    }
  });

  async function saveCredentials(overrides = {}) {
    try {
      const res = await api.post("/api/dns/namecheap/save", {
        api_user: overrides.api_user !== undefined ? overrides.api_user : inUser.value,
        api_key: overrides.api_key !== undefined ? overrides.api_key : inKey.value,
        client_ip: overrides.client_ip !== undefined ? overrides.client_ip : inClientIp.value,
        sandbox: overrides.sandbox !== undefined ? overrides.sandbox : selSandbox.value !== "false",
      });
      // Immediately wipe raw secrets from browser inputs; DOM shows masked summary only.
      inKey.value = "";
      inUser.value = "";
      inClientIp.value = "";
      vaultSignal.set(res);
      setSafeText(vaultStatusP, formatVaultStatusText(res));
      setAlert("pass", "Namecheap credentials encrypted with AES-256-GCM and stored in loopback SQLite vault.");
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  async function previewDns(overrides = {}) {
    try {
      const subVal = overrides.subdomain !== undefined ? overrides.subdomain : inSub.value;
      const res = await api.post("/api/dns/plan", {
        node_id: overrides.node_id || selNode.value || "vps-prod-01",
        domain: overrides.domain || inDomain.value,
        subdomain: subVal,
        target_ip: overrides.target_ip || inTargetIp.value,
        ttl: overrides.ttl || inTtl.value,
        edge_proxy: overrides.edge_proxy || selEdge.value,
        configure_www: overrides.configure_www !== undefined ? overrides.configure_www : String(subVal).trim() === "@",
      });
      dnsPlanSignal.set(res.plan);
      dnsApprovalSignal.set(res.approval_token || "");
      applyDnsBtn.disabled = false;
      applyDnsBtn.removeAttribute("disabled");
      renderDiffs(res.plan);
      setAlert("pass", `DNS plan ready: ${res.plan?.preserved_email_count || "0"} email records will remain untouched.`);
      return res;
    } catch (err) {
      applyDnsBtn.disabled = true;
      applyDnsBtn.setAttribute("disabled", "disabled");
      setAlert("error", err.message);
      throw err;
    }
  }

  async function applyDns(explicitToken) {
    const tok = explicitToken || dnsApprovalSignal.get();
    if (!tok) {
      const msg = "Preview DNS changes first to mint a single-use approval token.";
      setAlert("error", msg);
      throw new Error(msg);
    }
    try {
      const res = await api.post("/api/dns/apply", { approval_token: tok });
      dnsApprovalSignal.set("");
      applyDnsBtn.disabled = true;
      applyDnsBtn.setAttribute("disabled", "disabled");
      lastDnsSnapIdSignal.set(res.dns_snapshot_id || "");
      lastDnsRollbackTokSignal.set(res.rollback_approval_token || "");
      dnsSnapshotsSignal.set(res.snapshots || []);
      renderHistory();
      setAlert("pass", `DNS records applied cleanly. Pre-change snapshot ${res.dns_snapshot_id} saved.`);
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  async function checkPropagation(overrides = {}) {
    try {
      const res = await api.post("/api/dns/propagation/check", {
        node_id: overrides.node_id || selNode.value,
        domain: overrides.domain || inDomain.value,
        expected_ip: overrides.expected_ip || inTargetIp.value,
        edge_proxy: overrides.edge_proxy || selEdge.value,
      });
      const prop = res.propagation;
      propSignal.set(prop);
      setSafeText(propStatusP, prop?.message || "Propagation status updated.");
      if (prop && prop.propagated) {
        setAlert("pass", prop.message);
      } else {
        setAlert("error", prop?.message || "DNS has not finished propagating to target VPS yet.");
      }
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  async function planHttps(overrides = {}) {
    try {
      const res = await api.post("/api/https/plan", {
        node_id: overrides.node_id || selNode.value || "vps-prod-01",
        domain: overrides.domain || inDomain.value,
        expected_ip: overrides.expected_ip || inTargetIp.value,
        edge_proxy: overrides.edge_proxy || selEdge.value,
        workspace: overrides.workspace || inWorkspace.value,
        blueprint_id: overrides.blueprint_id || selBlueprint.value,
        dns_snapshot_id: overrides.dns_snapshot_id || lastDnsSnapIdSignal.get(),
        workers: overrides.workers || "2",
      });
      httpsPlanSignal.set(res.plan);
      httpsApprovalSignal.set(res.approval_token || "");
      applyHttpsBtn.disabled = false;
      applyHttpsBtn.removeAttribute("disabled");
      setSafeText(propStatusP, res.propagation?.message || "Live DNS propagation verified.");
      setAlert("pass", `Propagation verified for ${res.plan?.domain}. Auto-HTTPS rollout plan approved and ready.`);
      return res;
    } catch (err) {
      applyHttpsBtn.disabled = true;
      applyHttpsBtn.setAttribute("disabled", "disabled");
      setSafeText(propStatusP, err.message);
      setAlert("error", err.message);
      throw err;
    }
  }

  async function applyHttps(explicitToken) {
    const tok = explicitToken || httpsApprovalSignal.get();
    if (!tok) {
      const msg = "Run Preflight Propagation & Plan HTTPS first to mint an approval token.";
      setAlert("error", msg);
      throw new Error(msg);
    }
    try {
      const res = await api.post("/api/https/apply", { approval_token: tok });
      httpsApprovalSignal.set("");
      applyHttpsBtn.disabled = true;
      applyHttpsBtn.setAttribute("disabled", "disabled");
      httpsRolloutsSignal.set(res.rollouts || []);
      renderHistory();
      setAlert("pass", `Auto-HTTPS active for ${res.rollout?.domain} via ${res.rollout?.edge_proxy} (/_ready=${res.rollout?.ready_status || "200"}).`);
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  async function rollbackDns(dnsSnapshotId, approvalToken) {
    try {
      const res = await api.post("/api/dns/rollback", {
        dns_snapshot_id: dnsSnapshotId,
        approval_token: approvalToken,
      });
      lastDnsRollbackTokSignal.set("");
      dnsSnapshotsSignal.set(res.snapshots || []);
      renderHistory();
      setAlert("pass", `Restored prior Namecheap DNS records for ${res.rollback?.domain || dnsSnapshotId}.`);
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  async function rollbackHttps(rolloutId, approvalToken, dnsApprovalToken = "") {
    try {
      const dnsTok = dnsApprovalToken || lastDnsRollbackTokSignal.get();
      const res = await api.post("/api/https/rollback", {
        rollout_id: rolloutId,
        approval_token: approvalToken,
        rollback_dns: Boolean(dnsTok),
        dns_approval_token: dnsTok || "",
      });
      if (dnsTok) {
        lastDnsRollbackTokSignal.set("");
      }
      httpsRolloutsSignal.set(res.rollouts || []);
      if (res.dns_snapshots) {
        dnsSnapshotsSignal.set(res.dns_snapshots);
      }
      renderHistory();
      setAlert("pass", `Rolled back Auto-HTTPS rollout ${rolloutId} cleanly.`);
      return res;
    } catch (err) {
      setAlert("error", err.message);
      throw err;
    }
  }

  vaultForm.addEventListener("submit", (e) => {
    e.preventDefault();
    saveCredentials().catch(() => {});
  });

  dnsForm.addEventListener("submit", (e) => {
    e.preventDefault();
    previewDns().catch(() => {});
  });

  applyDnsBtn.addEventListener("click", () => {
    applyDns().catch(() => {});
  });

  checkPropBtn.addEventListener("click", () => {
    checkPropagation().catch(() => {});
  });

  planHttpsBtn.addEventListener("click", () => {
    planHttps().catch(() => {});
  });

  applyHttpsBtn.addEventListener("click", () => {
    applyHttps().catch(() => {});
  });

  async function loadInitial() {
    try {
      const st = await api.get("/api/dns/namecheap/status");
      vaultSignal.set(st);
      setSafeText(vaultStatusP, formatVaultStatusText(st));
    } catch (_) {
      // Optional before initial migration/start.
    }
    try {
      const hist = await api.get("/api/dns/snapshots");
      dnsSnapshotsSignal.set(hist.snapshots || []);
      httpsRolloutsSignal.set(hist.rollouts || []);
      renderHistory();
    } catch (_) {
      // Optional before initial migration/start.
    }
  }

  refreshNodes();

  return {
    element: section,
    refreshNodes,
    loadInitial,
    saveCredentials,
    previewDns,
    applyDns,
    checkPropagation,
    planHttps,
    applyHttps,
    rollbackDns,
    rollbackHttps,
    signals: {
      vaultSignal,
      dnsPlanSignal,
      propSignal,
      httpsPlanSignal,
      dnsSnapshotsSignal,
      httpsRolloutsSignal,
      statusSignal,
      errorSignal,
    },
  };
}
