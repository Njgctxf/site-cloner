/* sc_overrides.js - applies the edits made in the Studio inspector to a cloned page.
 *
 * Edits are stored as operations keyed by a structural CSS selector, per page path, in
 * window.__SC_OVERRIDES = {pages: {"/path": [op, ...]}}. They are applied after the page renders and
 * re-applied whenever the DOM changes, so they survive frameworks that re-render (React, Vue, Framer...).
 *
 *   {act: "text",  sel, value}          replace the element's text
 *   {act: "img",   sel, src}            replace an image (srcset/<source> removed)
 *   {act: "video", sel, src}            replace a video source
 *   {act: "link",  sel, href, text?}    change a link target (and its text)
 *   {act: "src",   sel, src}            change an iframe / embed address
 *   {act: "hide",  sel}                 hide the element
 *   {act: "dup",   sel}                 duplicate the element right after itself
 *   {act: "embed", sel, html}           replace the element by other markup (iframe, video, image)
 */
(() => {
  if (window.__scOverrides) return;
  const SC = window.__scOverrides = {};

  const norm = p => (p || "/").replace(/\/index\.html?$/i, "/").replace(/(.)\/+$/, "$1") || "/";
  SC.norm = norm;
  SC.ops = () => {
    const all = (window.__SC_OVERRIDES && window.__SC_OVERRIDES.pages) || {};
    return [...(all["*"] || []), ...(all[norm(location.pathname)] || [])];
  };

  const find = sel => { try { return document.querySelector(sel); } catch (e) { return null; } };

  function applyOne(op) {
    const el = find(op.sel);
    if (!el) return false;
    switch (op.act) {
      case "text":
        if (el.textContent !== op.value) el.textContent = op.value;
        break;
      case "img": {
        const img = el.tagName === "IMG" ? el : el.querySelector("img");
        if (!img) return false;
        if (img.getAttribute("src") !== op.src) {
          img.removeAttribute("srcset"); img.removeAttribute("sizes"); img.removeAttribute("loading");
          const pic = img.closest("picture");
          if (pic) pic.querySelectorAll("source").forEach(s => s.remove());
          img.setAttribute("src", op.src);
        }
        break;
      }
      case "video": {
        const v = el.tagName === "VIDEO" ? el : el.querySelector("video");
        if (!v) return false;
        if (v.getAttribute("src") !== op.src) {
          v.querySelectorAll("source").forEach(s => s.remove());
          v.setAttribute("src", op.src); v.load(); v.play && v.play().catch(() => {});
        }
        break;
      }
      case "link":
        if (op.href != null && el.getAttribute("href") !== op.href) el.setAttribute("href", op.href);
        if (op.text != null && el.textContent !== op.text) el.textContent = op.text;
        break;
      case "src":
        if (el.getAttribute("src") !== op.src) el.setAttribute("src", op.src);
        break;
      case "hide":
        if (el.style.getPropertyValue("display") !== "none") el.style.setProperty("display", "none", "important");
        break;
      case "dup": {
        const next = el.nextElementSibling;
        if (!(next && next.hasAttribute("data-sc-dup"))) {
          const c = el.cloneNode(true); c.setAttribute("data-sc-dup", "");
          el.after(c);
        }
        break;
      }
      case "embed": {
        const next = el.nextElementSibling;
        if (next && next.hasAttribute("data-sc-embed")) { if (next.__scHtml === op.html) break; next.remove(); }
        const r = el.getBoundingClientRect();
        const box = document.createElement("div");
        box.setAttribute("data-sc-embed", ""); box.__scHtml = op.html;
        box.style.cssText = `width:${Math.max(r.width, 1)}px;max-width:100%;height:${Math.max(r.height, 240)}px;position:relative;`;
        box.innerHTML = op.html;
        el.style.setProperty("display", "none", "important");
        el.after(box);
        break;
      }
    }
    return true;
  }

  SC.apply = (ops) => { let n = 0; for (const op of ops || SC.ops()) { try { if (applyOne(op)) n++; } catch (e) {} } return n; };

  let t = null, applying = false;
  const schedule = () => { if (applying) return; clearTimeout(t); t = setTimeout(() => { applying = true; SC.apply(); applying = false; }, 120); };
  SC.start = () => {
    if (SC.__started) return SC.apply();
    SC.__started = true;
    SC.apply();
    new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true, characterData: true});
    addEventListener("load", () => SC.apply());
    // client-side routers: re-apply after navigation
    for (const m of ["pushState", "replaceState"]) {
      const orig = history[m];
      history[m] = function () { const r = orig.apply(this, arguments); setTimeout(() => SC.apply(), 60); return r; };
    }
    addEventListener("popstate", () => setTimeout(() => SC.apply(), 60));
  };

  if (window.__SC_OVERRIDES) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", SC.start); else SC.start();
  }
})();
