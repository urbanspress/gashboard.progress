/**
 * Gashboard v0.1.0 — Exact-Decimal Wire & CSRF-Aware API Client (ADR-025c).
 * Preserves base-10 GrabDecimal/GrabInteger strings without IEEE-754 float coercion.
 */

export const GASHBOARD_VERSION = "0.1.0";

const EXACT_DECIMAL_RE = /^-?\d+(?:\.\d+)?$/;
const FLOAT_DRIFT_RE = /(?:0{5,}|9{5,})\d$/;

/**
 * Validate whether a wire value is an exact base-10 numeric string (ADR-025c).
 * Rejects JS numbers/floats and IEEE-754 drift patterns.
 * @param {unknown} value
 * @returns {boolean}
 */
export function isExactDecimalString(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!EXACT_DECIMAL_RE.test(trimmed)) return false;
  if (trimmed.includes(".") && FLOAT_DRIFT_RE.test(trimmed)) return false;
  return true;
}

/**
 * Recursively inspect designated numeric fields in a payload and reject raw JS floats or drift.
 * @param {unknown} obj
 * @param {Set<string>} [numericKeys]
 * @returns {{ ok: boolean, invalidKeys: string[] }}
 */
export function assertExactWireNumbers(
  obj,
  numericKeys = new Set([
    "cpu_pct",
    "ram_gb",
    "disk_gb",
    "grisp_workers",
    "ssh_port",
    "local_port",
    "remote_port",
    "ttl_minutes",
    "price",
    "amount",
  ])
) {
  const invalidKeys = [];
  const visit = (val, path) => {
    if (Array.isArray(val)) {
      val.forEach((item, idx) => visit(item, `${path}[${idx}]`));
      return;
    }
    if (!val || typeof val !== "object") return;
    for (const [k, v] of Object.entries(val)) {
      const nextPath = path ? `${path}.${k}` : k;
      if (numericKeys.has(k) && v !== undefined && v !== null && String(v).trim() !== "") {
        if (!isExactDecimalString(v)) {
          invalidKeys.push(nextPath);
        }
      } else if (v && typeof v === "object") {
        visit(v, nextPath);
      }
    }
  };
  visit(obj, "");
  return { ok: invalidKeys.length === 0, invalidKeys };
}

/**
 * Validate OpenSSH SHA256 host-key fingerprint format.
 * @param {string} fp
 * @returns {boolean}
 */
export function isValidSshFingerprint(fp) {
  return /^SHA256:[A-Za-z0-9+/]{16,64}={0,2}$/.test(String(fp || "").trim());
}

/**
 * Create a CSRF-enforcing JSON client targeting local Gashboard endpoints.
 */
export function createApiClient({ csrfToken = "", fetchImpl = globalThis.fetch } = {}) {
  const call = async (path, { method = "GET", body = null } = {}) => {
    const upper = String(method).toUpperCase();
    const headers = { Accept: "application/json" };
    const init = { method: upper, headers };
    if (upper !== "GET" && upper !== "HEAD") {
      headers["Content-Type"] = "application/json";
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken;
      }
      init.body = body === null ? "{}" : JSON.stringify(body);
    }
    const resp = await fetchImpl(path, init);
    const text = await resp.text();
    let parsed = {};
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = { ok: false, error: text || `HTTP ${resp.status}` };
    }
    if (!resp.ok) {
      const err = new Error(parsed.error || `HTTP ${resp.status}`);
      err.status = resp.status;
      err.payload = parsed;
      throw err;
    }
    return parsed;
  };

  return {
    get: (path) => call(path, { method: "GET" }),
    post: (path, body) => call(path, { method: "POST", body }),
  };
}
