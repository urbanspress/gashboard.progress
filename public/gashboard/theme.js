/**
 * Gashboard v0.2.0 — WCAG AA Light/Dark Theme Switcher powered by Grex JS v1.0.0.
 * Zero wrapper <div>s, zero innerHTML writes, zero FOUC, >= 4.5:1 verified contrast.
 */

import { computeContrastRatio, createTheme, signal } from "./grex.js";

const STORAGE_KEY = "gashboard_theme";
const VALID_MODES = new Set(["light", "dark"]);

export const THEME_PALETTES = Object.freeze({
  light: Object.freeze({
    bg: "#f8fafc",
    surface: "#ffffff",
    border: "#64748b",
    text: "#0f172a",
    muted: "#334155",
    primary: "#047857",
    primaryHover: "#065f46",
    btnFg: "#ffffff",
    link: "#047857",
    focus: "#065f46",
    danger: "#991b1b",
    dangerBg: "#fef2f2",
    dangerBtn: "#b91c1c",
    warn: "#92400e",
    warnBg: "#fffbeb",
    pass: "#065f46",
    passBg: "#ecfdf5",
  }),
  dark: Object.freeze({
    bg: "#0b1120",
    surface: "#111827",
    border: "#64748b",
    text: "#f8fafc",
    muted: "#cbd5e1",
    primary: "#047857",
    primaryHover: "#065f46",
    btnFg: "#ffffff",
    link: "#6ee7b7",
    focus: "#6ee7b7",
    danger: "#fecaca",
    dangerBg: "#7f1d1d",
    dangerBtn: "#991b1b",
    warn: "#fde68a",
    warnBg: "#78350f",
    pass: "#d1fae5",
    passBg: "#064e3b",
  }),
});

function toModeTokens(p) {
  return {
    focusRing: `3px solid ${p.focus}`,
    colors: {
      bg: p.bg,
      surface: p.surface,
      text: p.text,
      primary: p.primary,
      danger: p.dangerBtn,
    },
    tokens: {
      "--gash-bg": p.bg,
      "--gash-surface": p.surface,
      "--gash-border": p.border,
      "--gash-text": p.text,
      "--gash-muted": p.muted,
      "--gash-primary": p.primary,
      "--gash-primary-hover": p.primaryHover,
      "--gash-btn-fg": p.btnFg,
      "--gash-link": p.link,
      "--gash-focus": p.focus,
      "--gash-danger": p.danger,
      "--gash-danger-bg": p.dangerBg,
      "--gash-danger-btn": p.dangerBtn,
      "--gash-warn": p.warn,
      "--gash-warn-bg": p.warnBg,
      "--gash-pass": p.pass,
      "--gash-pass-bg": p.passBg,
    },
  };
}

export function createGashboardTheme() {
  return createTheme({
    focusRing: `3px solid ${THEME_PALETTES.light.focus}`,
    colors: THEME_PALETTES.light,
    modes: {
      light: toModeTokens(THEME_PALETTES.light),
      dark: toModeTokens(THEME_PALETTES.dark),
    },
  });
}

/**
 * Audit every foreground/background pair in the given palette against WCAG AA >= 4.5:1.
 * @param {"light"|"dark"} mode
 */
export function verifyThemeWcagContrast(mode = "light") {
  const clean = normalizeThemeMode(mode);
  const p = THEME_PALETTES[clean];
  const pairs = [
    ["text_on_bg", p.text, p.bg, 4.5],
    ["text_on_surface", p.text, p.surface, 4.5],
    ["muted_on_bg", p.muted, p.bg, 4.5],
    ["muted_on_surface", p.muted, p.surface, 4.5],
    ["link_on_surface", p.link, p.surface, 4.5],
    ["btn_fg_on_primary", p.btnFg, p.primary, 4.5],
    ["btn_fg_on_danger", p.btnFg, p.dangerBtn, 4.5],
    ["pass_on_pass_bg", p.pass, p.passBg, 4.5],
    ["warn_on_warn_bg", p.warn, p.warnBg, 4.5],
    ["danger_on_danger_bg", p.danger, p.dangerBg, 4.5],
  ];

  const checks = pairs.map(([pair, fg, bg, minRatio]) => {
    const ratio = computeContrastRatio(fg, bg);
    const pass = typeof ratio === "number" && ratio >= minRatio;
    return { pair, fg, bg, ratio: ratio ? Number(ratio.toFixed(2)) : 0, minRatio, pass };
  });
  return {
    mode: clean,
    ok: checks.every((c) => c.pass),
    checks,
  };
}

export function normalizeThemeMode(raw) {
  const s = String(raw || "").trim().toLowerCase();
  return VALID_MODES.has(s) ? s : "light";
}

function writeLocalTheme(win, mode) {
  try {
    const ls = win && win.localStorage;
    if (ls && typeof ls.setItem === "function") {
      ls.setItem(STORAGE_KEY, mode);
    }
  } catch {
    // Ignore storage quota / sandbox restrictions cleanly.
  }
}

/**
 * Initialize Gashboard's reactive Grex JS theme controller without FOUC.
 */
export function initThemeController({
  doc = globalThis.document,
  win = globalThis.window || globalThis,
  api = null,
  rootElement = null,
  onThemeChange = null,
} = {}) {
  const grexTheme = createGashboardTheme();
  const targetRoot =
    (doc && doc.documentElement) ||
    rootElement ||
    (doc && doc.body) ||
    null;

  const ssrAttr =
    targetRoot && typeof targetRoot.getAttribute === "function"
      ? String(targetRoot.getAttribute("data-grex-theme") || "").trim().toLowerCase()
      : "";
  const storedRaw = (() => {
    try {
      return win && win.localStorage && typeof win.localStorage.getItem === "function"
        ? String(win.localStorage.getItem(STORAGE_KEY) || "").trim().toLowerCase()
        : "";
    } catch {
      return "";
    }
  })();

  let initial = "light";
  if (VALID_MODES.has(ssrAttr)) {
    initial = ssrAttr;
  } else if (VALID_MODES.has(storedRaw)) {
    initial = storedRaw;
  }

  const modeSignal = signal(initial);

  const syncToggleButton = (mode) => {
    if (!doc || typeof doc.querySelector !== "function") return;
    const btn = doc.querySelector("#gashboard-theme-toggle");
    if (!btn) return;
    const isDark = mode === "dark";
    btn.setAttribute("aria-pressed", isDark ? "true" : "false");
    btn.setAttribute("data-active-theme", mode);
    btn.textContent = isDark ? "Switch to Light Mode" : "Switch to Dark Mode";
  };

  const applyMode = (nextRaw) => {
    const clean = normalizeThemeMode(nextRaw);
    modeSignal.set(clean);
    if (targetRoot && targetRoot.style) {
      grexTheme.applyTo(targetRoot, clean);
    } else if (targetRoot && typeof targetRoot.setAttribute === "function") {
      targetRoot.setAttribute("data-grex-theme", clean);
    }
    if (doc && doc.body && doc.body !== targetRoot && typeof doc.body.setAttribute === "function") {
      doc.body.setAttribute("data-grex-theme", clean);
    }
    writeLocalTheme(win, clean);
    syncToggleButton(clean);
    if (typeof onThemeChange === "function") {
      onThemeChange(clean);
    }
    return clean;
  };

  applyMode(initial);

  const persistMode = async (nextMode) => {
    const clean = applyMode(nextMode);
    if (api && typeof api.post === "function") {
      try {
        await api.post("/api/preferences/theme", { theme: clean });
      } catch {
        // Keep local UI theme applied cleanly even if offline.
      }
    }
    return clean;
  };

  const toggle = () => persistMode(modeSignal.get() === "dark" ? "light" : "dark");

  const attachToggleButton = () => {
    if (!doc || typeof doc.querySelector !== "function") return;
    const btn = doc.querySelector("#gashboard-theme-toggle");
    if (btn && !btn._gashThemeBound && typeof btn.addEventListener === "function") {
      btn._gashThemeBound = true;
      btn.addEventListener("click", () => {
        void toggle();
      });
    }
    syncToggleButton(modeSignal.get());
  };

  attachToggleButton();

  return {
    theme: grexTheme,
    getTheme: () => modeSignal.get(),
    setTheme: persistMode,
    toggle,
    attachToggleButton,
    verifyContrast: (m = modeSignal.get()) => verifyThemeWcagContrast(m),
    defaultSurfaceBg: () => THEME_PALETTES[modeSignal.get()].surface,
  };
}
