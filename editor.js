/* editor.js - in-place editor injected into a cloned page when it is opened with ?__edit=1.
 * Click a text to edit it, click an image to replace it, then "Enregistrer" writes the changes
 * into the cloned HTML file (POST /__save, handled by site_server.py).
 */
(() => {
  if (window.__scEditor) return;
  window.__scEditor = true;

  const texts = new Map();   // element -> {old, idx, now}  (insertion order = order of first edit)
  const imgs = new Map();    // element -> {old, idx, name, data}
  const baseline = new Map(); // element -> {old, idx} captured the first time a text is edited
  let editing = null;
  let pendingImg = null;
  let lastPick = null;

  // ---------- UI (shadow DOM so the page's CSS cannot touch it) ----------
  const host = document.createElement("div");
  host.id = "__sc_editor_host";
  host.style.cssText = "all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;";
  const ui = host.attachShadow({ mode: "open" });
  ui.innerHTML = `
    <style>
      *{box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
      .bar{position:fixed;top:12px;left:50%;transform:translateX(-50%);display:flex;align-items:center;gap:8px;
        background:#111827;color:#f9fafb;padding:8px 12px;border-radius:12px;font-size:13px;
        box-shadow:0 8px 30px rgba(0,0,0,.45);border:1px solid #374151;max-width:96vw;flex-wrap:wrap}
      .title{font-weight:700;margin-right:4px}
      select,button{font-size:13px;border-radius:8px;border:1px solid #4b5563;background:#1f2937;color:#f9fafb;padding:6px 10px;cursor:pointer}
      button.primary{background:#6366f1;border-color:#6366f1;font-weight:600}
      button:disabled{opacity:.45;cursor:default}
      .msg{font-size:12px;color:#9ca3af;max-width:340px}
      .msg.ok{color:#34d399}.msg.err{color:#f87171}
      .box{position:fixed;pointer-events:none;border:2px dashed #6366f1;background:rgba(99,102,241,.10);border-radius:3px;display:none}
      .tag{position:absolute;top:-22px;left:-2px;background:#6366f1;color:#fff;font-size:11px;padding:2px 6px;border-radius:4px;white-space:nowrap}
    </style>
    <div class="bar">
      <span class="title">✏️ Édition</span>
      <select id="pages" title="Pages du site"></select>
      <button id="save" class="primary" disabled>Enregistrer</button>
      <button id="undo" disabled>Annuler tout</button>
      <button id="exit">Quitter</button>
      <span class="msg" id="msg">Clique un texte ou une image pour la modifier.</span>
    </div>
    <div class="box" id="box"><span class="tag" id="tag"></span></div>
    <input type="file" id="file" accept="image/*" style="display:none">`;
  const $ = (id) => ui.getElementById(id);
  const msg = (t, cls) => { const m = $("msg"); m.textContent = t; m.className = "msg " + (cls || ""); };
  const inEditor = (el) => el === host || host.contains(el);

  // ---------- what can be edited ----------
  const SKIP = /^(SCRIPT|STYLE|HTML|BODY|HEAD|CANVAS|SVG|TEXTAREA|INPUT|NOSCRIPT|SELECT|OPTION)$/i;
  function textTarget(el) {
    if (!el || SKIP.test(el.tagName) || el.childNodes.length !== 1) return false;
    const n = el.firstChild;
    return n.nodeType === 3 && n.data.trim().length > 0;
  }
  function pick(x, y) {
    for (const el of document.elementsFromPoint(x, y)) {
      if (inEditor(el)) continue;
      if (el.tagName === "IMG") return { kind: "img", el };
      if (textTarget(el)) return { kind: "text", el };
    }
    return null;
  }

  // Position of a text node among all text nodes sharing the same (trimmed) text, in document order.
  function textIndex(node) {
    const key = node.data.trim();
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n = 0, cur;
    while ((cur = w.nextNode())) {
      if (cur === node) return n;
      if (/^(SCRIPT|STYLE|NOSCRIPT)$/i.test(cur.parentNode.tagName) || inEditor(cur.parentNode)) continue;
      if (cur.data.trim() === key) n++;
    }
    return n;
  }
  function imgIndex(el, src) {
    let n = 0;
    for (const im of document.images) {
      if (im === el) return n;
      if (!inEditor(im) && im.getAttribute("src") === src) n++;
    }
    return n;
  }

  // ---------- hover box ----------
  function showBox(p) {
    const box = $("box");
    if (!p) { box.style.display = "none"; return; }
    const r = p.el.getBoundingClientRect();
    Object.assign(box.style, { display: "block", left: r.left + "px", top: r.top + "px", width: r.width + "px", height: r.height + "px" });
    $("tag").textContent = p.kind === "img" ? "Image : clique pour remplacer" : "Texte : clique pour modifier";
  }
  let raf = 0;
  document.addEventListener("mousemove", (e) => {
    if (inEditor(e.target) || raf) return;
    raf = requestAnimationFrame(() => { raf = 0; lastPick = pick(e.clientX, e.clientY); showBox(editing ? null : lastPick); });
  }, true);

  // ---------- text editing ----------
  function startEdit(el) {
    if (editing && editing !== el) commit();
    if (!baseline.has(el)) baseline.set(el, { old: el.firstChild.data, idx: textIndex(el.firstChild) });
    editing = el;
    el.contentEditable = "true";
    el.spellcheck = false;
    el.style.outline = "2px solid #6366f1";
    el.focus();
    showBox(null);
  }
  function commit() {
    if (!editing) return;
    const el = editing;
    editing = null;
    el.removeAttribute("contenteditable");
    el.style.outline = "";
    const b = baseline.get(el);
    const now = el.textContent;
    if (now.trim() === b.old.trim()) texts.delete(el);
    else texts.set(el, { old: b.old, idx: b.idx, now });
    refresh();
  }

  // ---------- image replacing ----------
  $("file").addEventListener("change", () => {
    const f = $("file").files[0], el = pendingImg;
    $("file").value = "";
    if (!f || !el) return;
    const rd = new FileReader();
    rd.onload = () => {
      const prev = imgs.get(el);
      const old = prev ? prev.old : el.getAttribute("src");
      const idx = prev ? prev.idx : imgIndex(el, old);
      imgs.set(el, { old, idx, name: f.name, data: String(rd.result).split(",")[1] });
      el.removeAttribute("srcset");
      el.removeAttribute("sizes");
      if (el.parentElement && el.parentElement.tagName === "PICTURE") el.parentElement.querySelectorAll("source").forEach((s) => s.remove());
      el.src = rd.result;
      refresh();
    };
    rd.readAsDataURL(f);
  });

  // ---------- keep the page from reacting while editing ----------
  const BLOCK = ["click", "mousedown", "mouseup", "pointerdown", "pointerup", "dblclick", "auxclick", "touchstart", "touchend", "submit", "contextmenu"];
  BLOCK.forEach((type) => document.addEventListener(type, (e) => {
    if (inEditor(e.target)) return;
    if (editing && (e.target === editing || editing.contains(e.target))) { e.stopPropagation(); return; }
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    if (type !== "click") return;
    const p = pick(e.clientX, e.clientY);
    if (!p) { commit(); return; }
    if (p.kind === "text") startEdit(p.el);
    else { commit(); pendingImg = p.el; $("file").click(); }
  }, true));
  ["keydown", "keyup", "keypress"].forEach((type) => document.addEventListener(type, (e) => {
    if (!editing) { if (type === "keydown" && e.ctrlKey && e.key === "s") { e.preventDefault(); save(); } return; }
    e.stopPropagation();
    if (type !== "keydown") return;
    if (e.key === "Enter" || e.key === "Escape") { e.preventDefault(); commit(); }
    else if (e.ctrlKey && e.key === "s") { e.preventDefault(); commit(); save(); }
  }, true));

  // ---------- state / save ----------
  function pending() { return texts.size + imgs.size; }
  function refresh() {
    const n = pending();
    $("save").disabled = !n;
    $("undo").disabled = !n;
    $("save").textContent = n ? `Enregistrer (${n})` : "Enregistrer";
    if (n) msg(`${n} modification(s) non enregistrée(s).`);
  }
  async function save() {
    commit();
    if (!pending()) return;
    const changes = [
      ...[...texts.values()].map((c) => ({ type: "text", old: c.old, idx: c.idx, new: c.now })),
      ...[...imgs.values()].map((c) => ({ type: "img", old: c.old, idx: c.idx, name: c.name, data: c.data })),
    ];
    const els = [...texts.keys(), ...imgs.keys()];
    $("save").disabled = true;
    msg("Enregistrement...");
    try {
      const r = await fetch("/__save", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-SiteCloner-Editor": "1" },
        body: JSON.stringify({ page: location.pathname, changes }),
      });
      const out = await r.json();
      if (!r.ok) throw new Error(out.error || r.status);
      let ok = 0; const fails = [];
      out.results.forEach((res, i) => {
        if (!res.ok) { fails.push(res.msg); return; }
        ok++;
        const el = els[i];
        if (changes[i].type === "text") { texts.delete(el); baseline.delete(el); }
        else { imgs.delete(el); if (res.src) el.setAttribute("src", res.src); }
      });
      refresh();
      msg(fails.length ? `${ok} enregistrée(s), ${fails.length} échec(s) : ${fails[0]}` : `${ok} modification(s) enregistrée(s) dans le fichier.`, fails.length ? "err" : "ok");
    } catch (err) {
      refresh();
      msg("Échec : " + err.message, "err");
    }
  }
  $("save").addEventListener("click", save);
  $("undo").addEventListener("click", () => {
    if (confirm("Annuler toutes les modifications non enregistrées ? La page sera rechargée.")) location.reload();
  });
  function leave(url) {
    commit();
    if (pending() && !confirm("Des modifications ne sont pas enregistrées. Quitter quand même ?")) return false;
    window.onbeforeunload = null;
    location.href = url;
    return true;
  }
  $("exit").addEventListener("click", () => leave(location.pathname));
  window.addEventListener("beforeunload", (e) => { if (pending()) { e.preventDefault(); e.returnValue = ""; } });

  fetch("/__pages").then((r) => r.json()).then((list) => {
    const sel = $("pages");
    list.forEach((p) => {
      const o = document.createElement("option");
      o.value = p; o.textContent = p;
      if (p === location.pathname || p === location.pathname.replace(/\/$/, "") || p + "/" === location.pathname) o.selected = true;
      sel.appendChild(o);
    });
    if (list.length < 2) sel.style.display = "none";
    sel.addEventListener("change", () => { if (!leave(sel.value + "?__edit=1")) sel.value = location.pathname; });
  }).catch(() => { $("pages").style.display = "none"; });

  document.documentElement.appendChild(host);
})();
