/* inspector.js - bridge between a cloned page (opened with ?__inspect=1 in an iframe) and the Studio inspector.
 * Builds the page's component tree (blocks, then headings, texts, images, videos, 3D canvases, embeds, links,
 * buttons, forms), highlights what the Studio points at, lets the user pick elements in the page, and applies
 * edits live through sc_overrides.js (served together with this file).
 */
(() => {
  if (window.__scInspector) return;
  window.__scInspector = true;
  const SC = window.__scOverrides;
  const post = msg => parent.postMessage(Object.assign({sc: true}, msg), "*");
  const ids = new Map(), idOf = new WeakMap();
  let nextId = 1, selectMode = true, liveOps = [];

  // ---------- overlay (shadow DOM, ignored by the tree) ----------
  const host = document.createElement("div");
  host.setAttribute("data-sc-ui", "");
  host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483647;";
  const ui = host.attachShadow({mode: "open"});
  ui.innerHTML = `<style>
    .b{position:fixed;border:2px solid #7c6cff;background:rgba(124,108,255,.10);border-radius:3px;display:none;transition:all .06s}
    .s{border-color:#ff6fae;background:rgba(255,111,174,.10)}
    .t{position:absolute;top:-22px;left:-2px;background:#7c6cff;color:#fff;font:600 11px system-ui,sans-serif;padding:2px 7px;border-radius:4px;white-space:nowrap}
    .s .t{background:#ff6fae}</style>
    <div class="b" id="hov"><span class="t" id="hovt"></span></div><div class="b s" id="sel"><span class="t" id="selt"></span></div>`;
  const box = (name, el, label) => {
    const b = ui.getElementById(name);
    if (!el || !el.isConnected) { b.style.display = "none"; return; }
    const r = el.getBoundingClientRect();
    Object.assign(b.style, {display: "block", left: r.left + "px", top: r.top + "px", width: r.width + "px", height: r.height + "px"});
    ui.getElementById(name + "t").textContent = label || "";
  };
  let hovered = null, selected = null;
  const relayout = () => { box("hov", hovered && hovered.el, hovered && hovered.label); box("sel", selected && selected.el, selected && selected.label); };
  addEventListener("scroll", relayout, true); addEventListener("resize", relayout);

  // ---------- helpers ----------
  const visible = e => { if (!e || e.closest("[data-sc-ui]")) return false; const s = getComputedStyle(e); const r = e.getBoundingClientRect();
    return s.display !== "none" && s.visibility !== "hidden" && r.width > 0 && r.height > 0; };
  const txt = e => (e.innerText || e.textContent || "").replace(/\s+/g, " ").trim();
  const short = (s, n = 70) => s.length > n ? s.slice(0, n - 1) + "…" : s;
  function selOf(el) {
    const parts = [];
    while (el && el.nodeType === 1 && el !== document.body && el !== document.documentElement) {
      if (el.id && /^[A-Za-z][\w-]{1,40}$/.test(el.id) && !/\d{4,}/.test(el.id) && document.querySelectorAll("#" + CSS.escape(el.id)).length === 1) {
        parts.unshift("#" + CSS.escape(el.id)); return parts.join(" > ");
      }
      let i = 1, s = el;
      while ((s = s.previousElementSibling)) if (s.tagName === el.tagName) i++;
      parts.unshift(el.tagName.toLowerCase() + ":nth-of-type(" + i + ")");
      el = el.parentElement;
    }
    return "body > " + parts.join(" > ");
  }
  const reg = el => { let id = idOf.get(el); if (!id) { id = nextId++; idOf.set(el, id); } ids.set(id, el); return id; };
  const abs = u => { try { return new URL(u, location.href).href; } catch (e) { return u; } };

  // ---------- page blocks (same split as the Studio's section detection) ----------
  function blocks() {
    const vw = innerWidth;
    const vis = e => { const s = getComputedStyle(e); const r = e.getBoundingClientRect();
      return !e.hasAttribute("data-sc-ui") && s.display !== "none" && s.visibility !== "hidden" && r.height >= 40 && r.width > 0; };
    let root = document.body;
    for (let i = 0; i < 10; i++) {
      const kids = [...root.children].filter(vis);
      const h = root.getBoundingClientRect().height || 1;
      const big = kids.filter(e => e.getBoundingClientRect().height >= h * 0.8);
      if (kids.length === 1) { root = kids[0]; continue; }
      if (big.length === 1 && kids.length <= 4 && !["HEADER", "NAV", "FOOTER"].includes(big[0].tagName)) { root = big[0]; continue; }
      break;
    }
    const solid = e => { const s = getComputedStyle(e);
      if (s.position === "fixed" && !["HEADER", "NAV"].includes(e.tagName)) return !!e.querySelector("canvas");
      return txt(e).length > 0 || !!e.querySelector("img,svg,video,canvas,picture,iframe,model-viewer"); };
    const expand = (e, d) => {
      const r = e.getBoundingClientRect();
      if (d > 4 || ["HEADER", "NAV", "FOOTER"].includes(e.tagName) || r.height < innerHeight * 1.6) return [e];
      const kids = [...e.children].filter(k => vis(k) && solid(k) && k.getBoundingClientRect().height >= 60);
      if (kids.length === 1) { const inner = expand(kids[0], d + 1); return inner.length > 1 ? inner : [e]; }
      return kids.length >= 2 ? kids.flatMap(k => expand(k, d + 1)) : [e];
    };
    const list = [...root.children].filter(e => vis(e) && solid(e)).flatMap(e => expand(e, 0))
      .sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top);
    const out = [];
    for (const e of list) {
      const r = e.getBoundingClientRect();
      if (r.height < 60 || r.width < vw * 0.4) continue;
      const tag = e.tagName.toLowerCase();
      const kind = tag === "header" || tag === "nav" ? "En-tête" : tag === "footer" ? "Pied de page" :
        !out.some(o => o.kind === "Hero" || o.kind === "Section") && r.top + scrollY < innerHeight ? "Hero" : "Section";
      out.push({e, kind});
    }
    // a full-screen WebGL canvas fixed behind the page belongs to the tree too
    document.querySelectorAll("canvas").forEach(c => {
      const r = c.getBoundingClientRect();
      if (r.width >= innerWidth * 0.6 && r.height >= innerHeight * 0.6 && !out.some(o => o.e.contains(c))) out.unshift({e: c, kind: "Scène 3D"});
    });
    return out;
  }

  // ---------- items inside a block ----------
  const TEXT_TAGS = /^(P|LI|BLOCKQUOTE|FIGCAPTION|DT|DD|LABEL|SMALL|SPAN|DIV|STRONG|EM|TD|TH)$/;
  function classify(el) {
    const tag = el.tagName;
    if (/^H[1-6]$/.test(tag) && txt(el)) return {type: "heading", label: tag + " · " + short(txt(el))};
    if (tag === "IMG") { const r = el.getBoundingClientRect(); if (r.width < 24 || r.height < 24) return null;
      return {type: "image", label: short(el.alt || (el.currentSrc || el.src).split("/").pop().split("?")[0] || "image"), src: abs(el.currentSrc || el.src)}; }
    if (tag === "VIDEO") return {type: "video", label: "Vidéo", src: abs(el.currentSrc || el.src || (el.querySelector("source") || {}).src || "")};
    if (tag === "CANVAS") { const r = el.getBoundingClientRect(); if (r.width < 150 || r.height < 150) return null;
      return {type: "3d", label: `Canvas 3D / animation · ${Math.round(r.width)}×${Math.round(r.height)}`}; }
    if (tag === "MODEL-VIEWER" || tag === "SPLINE-VIEWER") return {type: "3d", label: tag.toLowerCase(), src: abs(el.getAttribute("src") || el.getAttribute("url") || "")};
    if (tag === "IFRAME") return {type: "embed", label: "Intégration · " + short((el.src || "").replace(/^https?:\/\//, ""), 50), src: el.src};
    if (tag === "A" && txt(el)) return {type: "link", label: short(txt(el), 50), href: el.getAttribute("href") || "", text: txt(el)};
    if (tag === "BUTTON" && txt(el)) return {type: "button", label: short(txt(el), 50), text: txt(el)};
    if (tag === "FORM") return {type: "form", label: "Formulaire"};
    if (TEXT_TAGS.test(tag) && el.childNodes.length && [...el.childNodes].every(n => n.nodeType === 3 || n.tagName === "BR")) {
      const t = txt(el); if (t.length >= 2) return {type: "text", label: short(t), text: t};
    }
    return null;
  }
  function items(block) {
    const out = [], seen = new Set();
    const walker = document.createTreeWalker(block, NodeFilter.SHOW_ELEMENT);
    let n = block;
    do {
      if (out.length >= 80) break;
      if (!(n instanceof Element) || n.closest("[data-sc-ui]")) continue;
      if ([...seen].some(s => s.contains(n))) continue;  // inside a link/button/form item already listed
      if (!visible(n) && n.tagName !== "CANVAS") continue;
      const c = classify(n);
      if (!c) continue;
      if (["link", "button", "image", "video", "embed", "3d"].includes(c.type)) seen.add(n);
      if (c.type === "heading" || c.type === "text") seen.add(n);
      out.push(Object.assign({id: reg(n), sel: selOf(n)}, c));
    } while ((n = walker.nextNode()));
    return out;
  }

  function models() {
    return [...new Set(performance.getEntriesByType("resource").map(e => e.name)
      .filter(u => /\.(glb|gltf|fbx|obj|usdz|splinecode)(\?|#|$)/i.test(u)))];
  }

  function tree() {
    ids.clear();
    const list = blocks().map(b => {
      const label = (b.e.querySelector && b.e.querySelector("h1,h2,h3") && txt(b.e.querySelector("h1,h2,h3"))) || b.e.getAttribute("aria-label") || "";
      return {id: reg(b.e), sel: selOf(b.e), kind: b.kind, label: short(label, 60),
              items: b.e.tagName === "CANVAS" ? [{id: reg(b.e), sel: selOf(b.e), type: "3d", label: "Scène 3D plein écran"}] : items(b.e)};
    });
    post({type: "tree", page: SC.norm(location.pathname), title: document.title, blocks: list, models: models()});
  }

  // ---------- page interaction ----------
  const nearest = el => { while (el && el !== document.body) { const id = idOf.get(el); if (id && ids.get(id) === el) return {id, el}; el = el.parentElement; } return null; };
  const labelFor = el => { const c = classify(el); return c ? c.label : el.tagName.toLowerCase(); };
  addEventListener("mousemove", e => {
    if (!selectMode) return;
    const hit = nearest(document.elementFromPoint(e.clientX, e.clientY));
    if (hit && (!hovered || hovered.el !== hit.el)) { hovered = {el: hit.el, label: labelFor(hit.el)}; relayout(); post({type: "hover", id: hit.id}); }
  }, true);
  const swallow = e => {
    if (!selectMode || e.target.closest && e.target.closest("[data-sc-ui]")) return;
    e.preventDefault(); e.stopPropagation(); e.stopImmediatePropagation();
    if (e.type === "click") { const hit = nearest(e.target); if (hit) { selected = {el: hit.el, label: labelFor(hit.el)}; relayout(); post({type: "select", id: hit.id}); } }
  };
  ["click", "mousedown", "mouseup", "pointerdown", "pointerup", "submit"].forEach(t => addEventListener(t, swallow, true));

  addEventListener("message", ev => {
    const m = ev.data;
    if (!m || !m.scParent) return;
    if (m.type === "hover") { const el = ids.get(m.id); hovered = el ? {el, label: labelFor(el)} : null; relayout(); }
    if (m.type === "select") {
      const el = ids.get(m.id); selected = el ? {el, label: labelFor(el)} : null;
      if (el) { const r = el.getBoundingClientRect(); if (r.top < 0 || r.bottom > innerHeight) el.scrollIntoView({block: "center", behavior: "smooth"}); setTimeout(relayout, 400); }
      relayout();
    }
    if (m.type === "mode") { selectMode = !!m.select; if (!selectMode) { hovered = null; relayout(); } }
    if (m.type === "apply") {
      liveOps = m.ops || [];
      window.__SC_OVERRIDES = {pages: {[SC.norm(location.pathname)]: liveOps}};
      SC.start();
      setTimeout(() => { relayout(); if (m.rebuild) tree(); }, 150);
    }
    if (m.type === "rebuild") tree();
  });

  // build when the page has settled, and again after client-side navigation
  // heavy assets (3D models) often arrive after the first pass: look again a little later
  let lastModels = "";
  const ready = () => {
    setTimeout(tree, 1200);
    [5000, 12000].forEach(ms => setTimeout(() => { const m = JSON.stringify(models()); if (m !== lastModels) { lastModels = m; tree(); } }, ms));
  };
  if (document.readyState === "complete") ready(); else addEventListener("load", ready);
  for (const fn of ["pushState", "replaceState"]) {
    const o = history[fn];
    history[fn] = function () { const r = o.apply(this, arguments); setTimeout(tree, 900); return r; };
  }
  addEventListener("popstate", () => setTimeout(tree, 900));
  document.documentElement.appendChild(host);
  post({type: "hello", page: SC.norm(location.pathname)});
})();
