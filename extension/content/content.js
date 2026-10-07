// Content-скрипт: только факты о странице и примитивные действия.
// Решения принимает Rust в background. Контракт: docs/content-contract.md.
// Методы форм вызываются через прототип: имя поля формы может их подменить.
if (!globalThis.leashRun) {
  const state = { v: 0, els: new Map() };
  const ROLES = new Set(["button", "link", "checkbox", "radio", "tab", "menuitem", "menuitemcheckbox",
    "menuitemradio", "option", "switch", "textbox", "searchbox", "combobox"]);
  const SELECTOR = "a[href], area[href], button, input:not([type=hidden]), select, textarea, summary, " +
    "[contenteditable]:not([contenteditable=false]), [role]";
  const attr = (el, name) => Element.prototype.getAttribute.call(el, name);
  const clip = (s, n) => (s || "").replace(/\s+/g, " ").trim().substring(0, n);

  const typeOf = (el) => (el.localName === "input" ? (attr(el, "type") || "text").toLowerCase() : "");

  const roleOf = (el) => {
    const explicit = (attr(el, "role") || "").trim().split(/\s+/)[0];
    if (ROLES.has(explicit)) return explicit;
    const tag = el.localName, type = typeOf(el);
    if ((tag === "a" || tag === "area") && el.hasAttribute("href")) return "link";
    if (tag === "button" || tag === "summary") return "button";
    if (tag === "select") return "combobox";
    if (tag === "textarea" || el.isContentEditable) return "textbox";
    if (tag !== "input") return "";
    if (type === "checkbox" || type === "radio") return type;
    if (["submit", "button", "reset", "image"].includes(type)) return "button";
    return type === "search" ? "searchbox" : "textbox";
  };

  const nameOf = (el) => {
    let n = attr(el, "aria-label");
    if (!n && attr(el, "aria-labelledby")) {
      n = attr(el, "aria-labelledby").trim().split(/\s+/)
        .map((id) => el.ownerDocument.getElementById(id)?.textContent || "").join(" ");
    }
    if (!n && el.labels?.length) n = Array.from(el.labels).map((l) => l.textContent).join(" ");
    n = clip(n || attr(el, "alt") || attr(el, "title") || attr(el, "placeholder") || el.innerText, 200);
    if (!n && el.localName === "input" && roleOf(el) === "button") n = clip(el.value, 200);
    return n;
  };

  const visible = (el) => {
    if (!el.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4 || r.right <= 0 || r.bottom + scrollY <= 0) return false;
    return !el.closest("[aria-hidden=true], [inert]");
  };

  const editable = (el) => el.localName === "textarea" || el.isContentEditable ||
    (el.localName === "input" && ["textbox", "searchbox"].includes(roleOf(el)));

  const submits = (el) => !!el.form && ((el.localName === "button" && el.type === "submit") ||
    (el.localName === "input" && ["submit", "image"].includes(typeOf(el))));

  const formAction = (el) => {
    if (!el.form) return "";
    const raw = (submits(el) && attr(el, "formaction")) || attr(el.form, "action") || "";
    try { return new URL(raw, document.baseURI).href; } catch { return "invalid:"; }
  };

  // Обход документа и открытых shadow root.
  const collect = (root, out) => {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    for (let el = w.nextNode(); el; el = w.nextNode()) {
      if (el.matches(SELECTOR) && roleOf(el) && visible(el)) out.push(el);
      if (el.shadowRoot) collect(el.shadowRoot, out);
    }
    return out;
  };

  // Факты, по которым background решает; перед действием сверяются все.
  const facts = (el) => ({
    tag: el.localName, role: roleOf(el), name: nameOf(el), type: typeOf(el),
    href: (el.localName === "a" || el.localName === "area") && el.hasAttribute("href") ? String(el.href) : "",
    form: !!el.form, formAction: formAction(el), submits: submits(el),
    autocomplete: (attr(el, "autocomplete") || "").toLowerCase(), editable: editable(el),
  });

  const snapshot = () => {
    state.v += 1;
    state.els = new Map();
    const found = collect(document.body, []);
    let truncated = found.length > 400;
    const elements = found.slice(0, 400).map((el, i) => {
      const id = i + 1, f = facts(el), r = el.getBoundingClientRect();
      const isSelect = f.tag === "select", hasValue = isSelect || f.tag === "textarea" || f.tag === "input";
      const value = hasValue && f.type !== "password" ? String(el.value).substring(0, 300) : "";
      const options = isSelect ? Array.from(el.options).slice(0, 50).map((o) => clip(o.text, 100)) : [];
      truncated ||= value.length === 300 || (isSelect && el.options.length > 50);
      state.els.set(id, el);
      return {
        id, ...f, value, options, disabled: el.matches(":disabled"),
        checked: f.type === "checkbox" || f.type === "radio" ? el.checked === true : false,
        inView: r.right > 0 && r.left < innerWidth && r.bottom > 0 && r.top < innerHeight,
      };
    });
    const parts = [];
    let size = 0;
    const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = tw.nextNode(); node && size <= 30000; node = tw.nextNode()) {
      const parent = node.parentElement;
      if (!parent || ["script", "style", "noscript", "template"].includes(parent.localName)) continue;
      const t = clip(node.textContent, 30000);
      if (!t || parseFloat(getComputedStyle(parent).fontSize) < 6 || !visible(parent)) continue;
      parts.push(t);
      size += t.length + 1;
    }
    const text = parts.join(" ");
    return {
      ok: true, origin: location.origin, url: location.href, title: clip(document.title, 300),
      version: state.v, elements, text: text.substring(0, 30000),
      frames: document.querySelectorAll("iframe, frame, object, embed").length,
      truncated: truncated || text.length > 30000,
    };
  };

  const act = (op) => {
    if (op.version !== state.v) return "stale";
    const el = state.els.get(op.id);
    if (!el || !el.isConnected) return "gone";
    const now = facts(el), keys = Object.keys(now);
    if (Object.keys(op.expect).length !== keys.length || keys.some((k) => now[k] !== op.expect[k])) return "changed";
    if (el.matches(":disabled")) return "disabled";
    if (!visible(el)) return "hidden";
    el.scrollIntoView({ block: "center" });
    const r = el.getBoundingClientRect(), root = el.getRootNode();
    const hit = (root.elementFromPoint ? root : document).elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (!hit || (hit !== el && !el.contains(hit))) return "occluded";
    if (op.action === "click") {
      el.click();
      return "";
    }
    if (op.action === "type") {
      if (!editable(el) || typeOf(el) === "file") return "unsupported";
      el.focus();
      if (el.isContentEditable) {
        el.textContent = op.text;
      } else {
        Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value").set.call(el, op.text);
      }
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      if (op.submit && el.form) HTMLFormElement.prototype.requestSubmit.call(el.form);
      return "";
    }
    if (op.action === "select" && el.localName === "select") {
      // Только по тексту, как его проверила политика, и только однозначно.
      const [opt, other] = Array.from(el.options).filter((o) => clip(o.text, 100) === op.text);
      if (!opt || other) return "no_option";
      el.value = opt.value;
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
      return "";
    }
    return "unsupported";
  };

  globalThis.leashRun = (op) => {
    try {
      if (op.op === "snapshot") return snapshot();
      if (location.origin !== op.origin) return { ok: false, reason: "origin" };
      if (op.op === "scroll") {
        scrollBy(0, (op.direction === "up" ? -0.8 : 0.8) * innerHeight);
        return { ok: true };
      }
      if (op.op !== "act") return { ok: false, reason: "unsupported" };
      const reason = act(op);
      return reason ? { ok: false, reason } : { ok: true };
    } catch {
      return { ok: false, reason: "error" };
    }
  };
}
undefined; // значение файла уходит в executeScript и обязано клонироваться: не функция
