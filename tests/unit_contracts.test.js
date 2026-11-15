import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  assertExactWireNumbers,
  createApiClient,
  GASHBOARD_VERSION,
  isExactDecimalString,
  isValidPaginationStrings,
  isValidSshFingerprint,
} from "../public/gashboard/api-client.js";
import { formatSafeConnectionHint } from "../public/gashboard/tunnels.js";
import { verifyThemeWcagContrast } from "../public/gashboard/theme.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").toUpperCase();
}

test("vendored Grex JS v1.0.0 runtime & manifest match C:\\Development\\grex-js\\dist SHA-256", () => {
  const vendoredJs = path.join(REPO_ROOT, "public", "gashboard", "grex.js");
  const vendoredManifest = path.join(REPO_ROOT, "public", "gashboard", "grex.elements.json");
  assert.equal(fs.existsSync(vendoredJs), true);
  assert.equal(fs.existsSync(vendoredManifest), true);

  assert.equal(
    sha256File(vendoredJs),
    "C1E28D74A7ECF19182E225644FA244AA8600658DD1FF8895C133BFC64976B6D6",
    "Vendored grex.js SHA-256 mismatch"
  );
  assert.equal(
    sha256File(vendoredManifest),
    "C54C4BCF15EC8FEA2DEC4EF41975BA85A4B555DD400604E59C78883A8BBDEBC9",
    "Vendored grex.elements.json SHA-256 mismatch"
  );

  const upstreamJs = "C:\\Development\\grex-js\\dist\\grex-js-v1.0.0.js";
  const upstreamManifest = "C:\\Development\\grex-js\\dist\\grex.elements.json";
  if (fs.existsSync(upstreamJs)) {
    assert.equal(sha256File(vendoredJs), sha256File(upstreamJs));
  }
  if (fs.existsSync(upstreamManifest)) {
    assert.equal(sha256File(vendoredManifest), sha256File(upstreamManifest));
  }
});

test("ADR-025c exact base-10 numeric wire validation rejects floats and precision drift", () => {
  assert.equal(GASHBOARD_VERSION, "0.3.0");
  assert.equal(isExactDecimalString("1000.00"), true);
  assert.equal(isExactDecimalString("12345678901234567890.1234"), true);
  assert.equal(isExactDecimalString("9007199254740993"), true);
  assert.equal(isExactDecimalString("19.99"), true);
  assert.equal(isExactDecimalString("22"), true);
  assert.equal(isExactDecimalString("0"), true);

  assert.equal(isValidPaginationStrings("1", "25"), true);
  assert.equal(isValidPaginationStrings("2", "100"), true);
  assert.equal(isValidPaginationStrings("1", "101"), false);
  assert.equal(isValidPaginationStrings("0", "25"), false);
  assert.equal(isValidPaginationStrings(1, 25), false);
  assert.equal(isValidPaginationStrings("1.5", "25"), false);

  const lightWcag = verifyThemeWcagContrast("light");
  const darkWcag = verifyThemeWcagContrast("dark");
  assert.equal(lightWcag.ok, true, `Light palette WCAG AA failed: ${JSON.stringify(lightWcag.checks)}`);
  assert.equal(darkWcag.ok, true, `Dark palette WCAG AA failed: ${JSON.stringify(darkWcag.checks)}`);

  // Reject raw JS numbers / floats and IEEE-754 drift patterns
  assert.equal(isExactDecimalString(19.99), false);
  assert.equal(isExactDecimalString(22), false);
  assert.equal(isExactDecimalString("19.990000000000002"), false);
  assert.equal(isExactDecimalString("0.30000000000000004"), false);
  assert.equal(isExactDecimalString("12.34.56"), false);

  const okRes = assertExactWireNumbers({
    cpu_pct: "14.25",
    ram_gb: "8.00",
    grisp_workers: "4",
    nested: { local_port: "15432", price: "1000.00" },
  });
  assert.equal(okRes.ok, true);

  const badRes = assertExactWireNumbers({
    cpu_pct: 14.25,
    nested: { price: "19.990000000000002" },
    ttl: 300,
    preserved_email_count: 2,
    workers: 4,
  });
  assert.equal(badRes.ok, false);
  assert.deepEqual(badRes.invalidKeys, ["cpu_pct", "nested.price", "ttl", "preserved_email_count", "workers"]);

  const okDnsRes = assertExactWireNumbers({
    ttl: "300",
    preserved_email_count: "3",
    preserved_other_count: "1",
    workers: "2",
  });
  assert.equal(okDnsRes.ok, true);
});

test("SSH fingerprint validator & tunnel hint generator never leak credentials", () => {
  assert.equal(isValidSshFingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"), true);
  assert.equal(isValidSshFingerprint("SHA256:short"), false);
  assert.equal(isValidSshFingerprint("MD5:aa:bb:cc"), false);

  const pgHint = formatSafeConnectionHint({ engine: "postgres", local_host: "127.0.0.1", local_port: "15432" });
  assert.equal(pgHint, "psql -h 127.0.0.1 -p 15432 -U <db_user> <database>");
  const mariaHint = formatSafeConnectionHint({ engine: "mariadb", local_host: "127.0.0.1", local_port: "13306" });
  assert.equal(mariaHint, "mariadb --host=127.0.0.1 --port=13306 --user=<db_user> <database>");
  const redisHint = formatSafeConnectionHint({ engine: "redis", local_host: "127.0.0.1", local_port: "16379" });
  assert.equal(redisHint, "redis-cli -h 127.0.0.1 -p 16379");
});

test("createApiClient injects X-CSRF-Token on POST and surfaces server error codes", async () => {
  let capturedInit = null;
  const api = createApiClient({
    csrfToken: "tok-123",
    fetchImpl: async (_url, init) => {
      capturedInit = init;
      return { ok: false, status: 409, text: async () => JSON.stringify({ ok: false, error: "Token replay" }) };
    },
  });

  await assert.rejects(() => api.post("/api/fleet/rollback", { snapshot_id: "snap-1" }), (err) => {
    assert.equal(err.status, 409);
    assert.match(err.message, /Token replay/);
    return true;
  });
  assert.equal(capturedInit.headers["X-CSRF-Token"], "tok-123");
});
