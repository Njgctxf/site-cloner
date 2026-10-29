/* ui.js - small helpers shared by every page: scroll reveal, cursor spotlight, ripple, toasts, modals, count-up. */
(() => {
  const UI = window.UI = {};

  // Reveal elements with [data-reveal] when they enter the viewport; [data-stagger] staggers its children.
  const io = "IntersectionObserver" in window ? new IntersectionObserver(es => {
    for (const e of es) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, {threshold: .08, rootMargin: "0px 0px -40px 0px"}) : null;
  UI.reveal = (root = document) => {
    root.querySelectorAll("[data-stagger]").forEach(p => {
      [...p.children].forEach((c, i) => { if (!c.hasAttribute("data-reveal")) c.setAttribute("data-reveal", p.dataset.stagger || ""); c.style.setProperty("--d", `${Math.min(i, 12) * 0.06}s`); });
    });
    root.querySelectorAll("[data-reveal]:not(.in)").forEach(el => io ? io.observe(el) : el.classList.add("in"));
  };

  // Cursor spotlight on .ui-spot surfaces
  document.addEventListener("pointermove", e => {
    const el = e.target.closest && e.target.closest(".ui-spot");
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  }, {passive: true});

  // Ripple on buttons
  document.addEventListener("pointerdown", e => {
    const b = e.target.closest && e.target.closest(".ui-btn");
    if (!b) return;
    const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height);
    const k = document.createElement("span");
    k.className = "ripple";
    k.style.cssText = `width:${s}px;height:${s}px;left:${e.clientX - r.left - s / 2}px;top:${e.clientY - r.top - s / 2}px`;
    b.appendChild(k);
    setTimeout(() => k.remove(), 650);
  });

  // Toasts
  UI.toast = (msg, kind = "") => {
    let box = document.querySelector(".ui-toasts");
    if (!box) { box = document.createElement("div"); box.className = "ui-toasts"; document.body.appendChild(box); }
    const t = document.createElement("div");
    t.className = `ui-toast ${kind}`;
    t.innerHTML = `<span>${kind === "ok" ? "✅" : kind === "err" ? "⚠️" : "✨"}</span><span></span>`;
    t.lastChild.textContent = msg;
    box.appendChild(t);
    setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 320); }, 3200);
  };

  // Modals: <div class="ui-modal" id="x"><div class="box ui-card">...</div></div>
  UI.open = id => { const m = document.getElementById(id); if (m) { m.classList.add("open"); document.body.style.overflow = "hidden"; } };
  UI.close = id => {
    const ms = id ? [document.getElementById(id)] : document.querySelectorAll(".ui-modal.open");
    ms.forEach(m => m && m.classList.remove("open"));
    if (!document.querySelector(".ui-modal.open")) document.body.style.overflow = "";
  };
  document.addEventListener("click", e => {
    if (e.target.classList && e.target.classList.contains("ui-modal")) UI.close(e.target.id);
    const c = e.target.closest && e.target.closest("[data-close]");
    if (c) UI.close(c.closest(".ui-modal") && c.closest(".ui-modal").id);
  });
  document.addEventListener("keydown", e => { if (e.key === "Escape") UI.close(); });

  // In-page confirm dialog (window.confirm is blocked in embedded browsers): await UI.confirm("…") -> true/false
  UI.confirm = (msg, {ok = "Confirmer", danger = true} = {}) => new Promise(resolve => {
    const m = document.createElement("div");
    m.className = "ui-modal";
    m.innerHTML = `<div class="box ui-card" style="width:min(420px,100%);padding:24px">
      <p style="margin:0 0 20px;line-height:1.5;font-size:.98rem"></p>
      <div style="display:flex;gap:10px;justify-content:flex-end">
        <button class="ui-btn ghost" data-r="0">Annuler</button>
        <button class="ui-btn ${danger ? "danger" : "primary"}" data-r="1"></button>
      </div></div>`;
    m.querySelector("p").textContent = msg;
    m.querySelector('[data-r="1"]').textContent = ok;
    const done = v => { m.classList.remove("open"); setTimeout(() => m.remove(), 300); document.removeEventListener("keydown", key, true); resolve(v); };
    const key = e => { if (e.key === "Escape") { e.stopPropagation(); done(false); } if (e.key === "Enter") { e.preventDefault(); done(true); } };
    m.addEventListener("click", e => { const b = e.target.closest("[data-r]"); if (b) done(b.dataset.r === "1"); else if (e.target === m) done(false); });
    document.addEventListener("keydown", key, true);
    document.body.appendChild(m);
    requestAnimationFrame(() => { m.classList.add("open"); m.querySelector('[data-r="1"]').focus(); });
  });

  // Animated numbers: <span data-count="1234">
  UI.count = (root = document) => root.querySelectorAll("[data-count]").forEach(el => {
    const raw = el.dataset.count, end = parseFloat(raw);
    if (isNaN(end)) { el.textContent = raw; return; }
    const t0 = performance.now(), dur = 1100;
    const step = now => {
      const p = Math.min(1, (now - t0) / dur), v = end * (1 - Math.pow(1 - p, 3));
      el.textContent = Number.isInteger(end) ? Math.round(v).toLocaleString("fr-FR") : v.toFixed(2).replace(".", ",");
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });

  UI.esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));

  // Backdrop: add the aurora + grid once per page
  UI.backdrop = () => {
    if (document.querySelector(".ui-aurora")) return;
    const a = document.createElement("div"); a.className = "ui-aurora"; a.innerHTML = "<i></i>";
    const g = document.createElement("div"); g.className = "ui-grid-bg";
    document.body.prepend(g); document.body.prepend(a);
  };

  const boot = () => { if (document.body.classList.contains("ui")) UI.backdrop(); UI.reveal(); UI.count(); };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
