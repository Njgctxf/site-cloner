/* ui.js - shared helpers across SiteCloner SaaS: theme sync (Bleu/Violet), cosmic stars, scroll reveal, spotlight, ripple, toasts, modals. */
(() => {
  const UI = window.UI = {};
  const THEME_KEY = "sc_home_theme";

  UI.getTheme = () => {
    try { return localStorage.getItem(THEME_KEY) === "violet" ? "violet" : "blue"; } catch { return "blue"; }
  };

  UI.setTheme = (mode) => {
    const isViolet = mode === "violet";
    document.body.classList.toggle("theme-violet", isViolet);
    try { localStorage.setItem(THEME_KEY, isViolet ? "violet" : "blue"); } catch {}
    document.querySelectorAll(".sc-theme-btn[data-theme]").forEach(btn => {
      btn.classList.toggle("on", btn.dataset.theme === (isViolet ? "violet" : "blue"));
    });
    document.dispatchEvent(new CustomEvent("sc-theme", { detail: { theme: isViolet ? "violet" : "blue" } }));
  };

  // Reveal elements with [data-reveal]
  const io = "IntersectionObserver" in window ? new IntersectionObserver(es => {
    for (const e of es) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, {threshold: .08, rootMargin: "0px 0px -40px 0px"}) : null;

  UI.reveal = (root = document) => {
    root.querySelectorAll("[data-stagger]").forEach(p => {
      [...p.children].forEach((c, i) => {
        if (!c.hasAttribute("data-reveal")) c.setAttribute("data-reveal", p.dataset.stagger || "");
        c.style.setProperty("--d", `${Math.min(i, 12) * 0.06}s`);
      });
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

  // Clean SVG Toasts (Zero Emojis)
  const SVG_OK = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--ok);flex-shrink:0"><path d="M20 6L9 17l-5-5"/></svg>`;
  const SVG_ERR = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--danger);flex-shrink:0"><circle cx="12" cy="12" r="9"/><path d="M12 8v4m0 4h.01"/></svg>`;
  const SVG_INFO = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent);flex-shrink:0"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4m0-4h.01"/></svg>`;

  UI.toast = (msg, kind = "") => {
    let box = document.querySelector(".ui-toasts");
    if (!box) { box = document.createElement("div"); box.className = "ui-toasts"; document.body.appendChild(box); }
    const t = document.createElement("div");
    t.className = `ui-toast ${kind}`;
    t.innerHTML = `${kind === "ok" ? SVG_OK : kind === "err" ? SVG_ERR : SVG_INFO}<span></span>`;
    t.lastChild.textContent = msg;
    box.appendChild(t);
    setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 320); }, 3200);
  };

  // Modals
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

  // Subtle cosmic starfield + nebula backdrop
  UI.backdrop = () => {
    if (!document.querySelector(".ui-aurora")) {
      const a = document.createElement("div"); a.className = "ui-aurora"; a.innerHTML = "<i></i>";
      const g = document.createElement("div"); g.className = "ui-grid-bg";
      document.body.prepend(g);
      document.body.prepend(a);
    }
    if (!document.querySelector(".ui-stars-canvas") && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      const c = document.createElement("canvas");
      c.className = "ui-stars-canvas";
      document.body.prepend(c);
      const ctx = c.getContext("2d");
      if (ctx) {
        let w = 0, h = 0;
        const stars = Array.from({ length: 85 }, () => ({
          x: Math.random(), y: Math.random(),
          r: 0.55 + Math.random() * 1.25,
          a: 0.22 + Math.random() * 0.55,
          sp: 0.5 + Math.random() * 1.8,
          ph: Math.random() * Math.PI * 2,
        }));
        const resize = () => { w = c.width = window.innerWidth; h = c.height = window.innerHeight; };
        resize();
        window.addEventListener("resize", resize);
        const draw = (t) => {
          if (!document.hidden) {
            ctx.clearRect(0, 0, w, h);
            const violet = document.body.classList.contains("theme-violet");
            for (const s of stars) {
              const tw = 0.45 + 0.55 * Math.sin(t * 0.0012 * s.sp + s.ph);
              ctx.fillStyle = violet ? `rgba(216, 200, 255, ${(s.a * tw).toFixed(3)})` : `rgba(210, 232, 255, ${(s.a * tw).toFixed(3)})`;
              ctx.beginPath();
              ctx.arc(s.x * w, s.y * h, s.r, 0, Math.PI * 2);
              ctx.fill();
            }
          }
          requestAnimationFrame(draw);
        };
        requestAnimationFrame(draw);
      }
    }
  };

  // Inject compact Bleu / Violet theme toggle into .ui-nav or sidebar footer
  UI.mountThemeSwitch = () => {
    if (document.querySelector(".sc-theme-switch")) return;
    const host = document.querySelector(".ui-nav") || document.querySelector(".side .bottom");
    if (!host) return;
    const wrap = document.createElement("div");
    wrap.className = "sc-theme-switch";
    wrap.setAttribute("role", "group");
    wrap.setAttribute("aria-label", "Couleur du fond");
    wrap.innerHTML = `
      <button type="button" class="sc-theme-btn" data-theme="blue" title="Bleu Cosmique"><span class="dot" style="background:#38bdf8"></span>Bleu</button>
      <button type="button" class="sc-theme-btn" data-theme="violet" title="Violet Sidéral"><span class="dot" style="background:#8a72ff"></span>Violet</button>
    `;
    wrap.addEventListener("click", e => {
      const btn = e.target.closest(".sc-theme-btn[data-theme]");
      if (btn) UI.setTheme(btn.dataset.theme);
    });
    if (host.classList.contains("bottom")) {
      wrap.style.marginTop = "8px";
      wrap.style.alignSelf = "flex-start";
    }
    host.appendChild(wrap);
    UI.setTheme(UI.getTheme());
  };

  const ensureFavicon = () => {
    if (!document.querySelector('link[rel="icon"]')) {
      const l = document.createElement("link");
      l.rel = "icon"; l.type = "image/svg+xml"; l.href = "/__sc/static/reflex/img/brand-orbit.svg";
      document.head.appendChild(l);
    }
  };

  UI.typewriter = (el, phrases) => {
    if (!el || !phrases || !phrases.length) return;
    let pIdx = 0, cIdx = 0, erasing = false;
    function tick() {
      const text = phrases[pIdx];
      if (!erasing) {
        cIdx++;
        el.textContent = text.slice(0, cIdx);
        if (cIdx === text.length) { erasing = true; setTimeout(tick, 1800); return; }
        setTimeout(tick, 38 + Math.random() * 20);
      } else {
        cIdx--;
        el.textContent = text.slice(0, cIdx);
        if (cIdx === 0) { erasing = false; pIdx = (pIdx + 1) % phrases.length; setTimeout(tick, 340); return; }
        setTimeout(tick, 22);
      }
    }
    tick();
  };

  UI.mountAccountNav = () => {
    if (document.querySelector(".sc-acc-wrap")) return;
    const nav = document.querySelector(".ui-nav");
    if (!nav) return;
    const wrap = document.createElement("div");
    wrap.className = "sc-acc-wrap";
    wrap.innerHTML = `<a class="sc-acc-btn" href="/account/login">Connexion</a><a class="sc-acc-btn primary" href="/account/register">Créer un compte</a>`;
    const themeSwitch = nav.querySelector(".sc-theme-switch");
    if (themeSwitch) nav.insertBefore(wrap, themeSwitch);
    else nav.appendChild(wrap);

    fetch("/account/api/me", { credentials: "same-origin" })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        window.__scCurrentUser = data.user || null;
        document.dispatchEvent(new CustomEvent("sc-account", { detail: data }));
        if (data.authenticated && data.user) {
          const u = data.user;
          const avHtml = u.avatar_url
            ? `<span class="sc-acc-av"><img src="${UI.esc(u.avatar_url)}" alt=""></span>`
            : `<span class="sc-acc-av" style="background:${UI.esc(u.avatar_color || "#6366f1")}">${UI.esc(u.initials || "U")}</span>`;
          wrap.innerHTML = `<a class="sc-acc-pill" href="/account/profile" title="Mon profil (@${UI.esc(u.username)})">${avHtml}<span>${UI.esc(u.display_name || u.username)}</span></a>`;
        }
      })
      .catch(() => {});
  };

  const boot = () => {
    ensureFavicon();
    UI.setTheme(UI.getTheme());
    if (document.body.classList.contains("ui")) UI.backdrop();
    UI.mountThemeSwitch();
    UI.mountAccountNav();
    document.querySelectorAll("[data-typewriter]").forEach(host => {
      try {
        const phrases = JSON.parse(host.dataset.typewriter || "[]");
        const target = host.querySelector(".ui-type-text") || host;
        UI.typewriter(target, phrases);
      } catch (_) {}
    });
    UI.reveal();
    UI.count();
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
