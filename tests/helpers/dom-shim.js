/**
 * Minimal zero-dependency DOM shim for Gashboard Pure Grex JS UI tests.
 * Traps .innerHTML writes, provides localName + "*" querySelectorAll for Grex auditDom(),
 * and avoids any Node bundler or browser dependency.
 */

function parseAttrSelector(part) {
  const m = part.match(/^([a-zA-Z0-9_-]*)\[([a-zA-Z0-9_-]+)(?:=["']([^"']*)["'])?\]$/);
  if (!m) return null;
  return { tag: m[1].toLowerCase(), attr: m[2], val: m[3] };
}

function matchesSingleToken(el, token) {
  const t = token.trim();
  if (!t || t === "*") return true;
  if (t.startsWith("#")) return el.id === t.slice(1);
  if (t.startsWith(".")) return el.classList.includes(t.slice(1));
  const attrSel = parseAttrSelector(t);
  if (attrSel) {
    if (attrSel.tag && el.localName !== attrSel.tag) return false;
    if (!el.hasAttribute(attrSel.attr)) return false;
    if (attrSel.val !== undefined) return el.getAttribute(attrSel.attr) === attrSel.val;
    return true;
  }
  const dotIdx = t.indexOf(".");
  if (dotIdx > 0) {
    const tag = t.slice(0, dotIdx).toLowerCase();
    const cls = t.slice(dotIdx + 1);
    return el.localName === tag && el.classList.includes(cls);
  }
  return el.localName === t.toLowerCase();
}

export class DomTextNode {
  constructor(text, ownerDocument) {
    this.nodeType = 3;
    this.nodeValue = String(text);
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
  }
  get textContent() {
    return this.nodeValue;
  }
  set textContent(v) {
    this.nodeValue = String(v ?? "");
  }
}

export class DomElement {
  constructor(tagName, ownerDocument) {
    this.nodeType = 1;
    this.tagName = String(tagName).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.parentNode = null;
    this.childNodes = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.value = "";
    const styleProps = new Map();
    this.style = {
      setProperty(k, v) {
        styleProps.set(String(k), String(v));
      },
      getPropertyValue(k) {
        return styleProps.get(String(k)) || "";
      },
      removeProperty(k) {
        const prev = styleProps.get(String(k)) || "";
        styleProps.delete(String(k));
        return prev;
      },
    };
  }

  get localName() {
    return this.tagName.toLowerCase();
  }

  get children() {
    return this.childNodes.filter((n) => n.nodeType === 1);
  }

  get firstChild() {
    return this.childNodes[0] || null;
  }

  get id() {
    return this.attributes.get("id") || "";
  }

  set id(val) {
    this.setAttribute("id", val);
  }

  get className() {
    return this.attributes.get("class") || "";
  }

  get classList() {
    return this.className.split(/\s+/).filter(Boolean);
  }

  get innerHTML() {
    return "";
  }

  set innerHTML(val) {
    if (this.ownerDocument) {
      this.ownerDocument.innerHTMLWriteCount += 1;
    }
    throw new Error(`Unsafe innerHTML write blocked on <${this.localName}>: ${String(val).slice(0, 64)}`);
  }

  get textContent() {
    return this.childNodes.map((n) => n.textContent).join("");
  }

  set textContent(val) {
    this.childNodes = [];
    if (val !== undefined && val !== null && String(val) !== "") {
      this.appendChild(new DomTextNode(String(val), this.ownerDocument));
    }
  }

  setAttribute(name, value) {
    const k = String(name);
    const v = String(value);
    this.attributes.set(k, v);
    if (k === "value") {
      this.value = v;
    }
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  appendChild(node) {
    if (node.parentNode && typeof node.parentNode.removeChild === "function") {
      node.parentNode.removeChild(node);
    }
    node.parentNode = this;
    this.childNodes.push(node);
    return node;
  }

  removeChild(node) {
    const idx = this.childNodes.indexOf(node);
    if (idx >= 0) {
      this.childNodes.splice(idx, 1);
      node.parentNode = null;
    }
    return node;
  }

  addEventListener(type, fn) {
    const k = String(type);
    if (!this.listeners.has(k)) {
      this.listeners.set(k, []);
    }
    this.listeners.get(k).push(fn);
  }

  dispatchEvent(evt) {
    const type = typeof evt === "string" ? evt : evt.type;
    const fns = this.listeners.get(type) || [];
    for (const fn of fns) {
      fn.call(this, typeof evt === "object" ? evt : { type, target: this });
    }
    return true;
  }

  click() {
    return this.dispatchEvent({ type: "click", target: this });
  }

  querySelectorAll(selector) {
    const selectors = String(selector)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const results = [];
    const visit = (node) => {
      for (const child of node.children) {
        if (selectors.some((sel) => matchesSingleToken(child, sel))) {
          results.push(child);
        }
        visit(child);
      }
    };
    visit(this);
    return results;
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}

export class DomDocument {
  constructor() {
    this.innerHTMLWriteCount = 0;
    this.documentElement = new DomElement("html", this);
    this.head = new DomElement("head", this);
    this.body = new DomElement("body", this);
    this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
  }

  createElement(tag) {
    return new DomElement(tag, this);
  }

  createTextNode(text) {
    return new DomTextNode(text, this);
  }

  getElementById(id) {
    const target = String(id);
    const search = (node) => {
      for (const child of node.children) {
        if (child.id === target) return child;
        const nested = search(child);
        if (nested) return nested;
      }
      return null;
    };
    return search(this.body) || search(this.head);
  }

  querySelectorAll(selector) {
    return [...this.head.querySelectorAll(selector), ...this.body.querySelectorAll(selector)];
  }

  querySelector(selector) {
    return this.querySelectorAll(selector)[0] || null;
  }
}
