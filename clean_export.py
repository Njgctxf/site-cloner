"""
clean_export.py - turn a cloned page (or one of its sections) into clean, editable code.

The page is rendered in Chrome, then:
  * only the CSS rules that actually apply to the exported elements are kept (plus their @font-face,
    @keyframes and :root variables), pretty-printed;
  * the HTML is a cleaned copy of the rendered DOM: no scripts, no framework/tracking attributes, no inline
    styles left behind by animation libraries, lazy images resolved, indented;
  * the same markup is converted to a React component (JSX);
  * the site's design tokens are written as a Tailwind config.
"""

import html as htmlmod
import json
import re
from html.parser import HTMLParser

CLEAN_JS = r"""(n) => {
  const blocks = window.__scBlocks ? window.__scBlocks() : [];
  const whole = n === null || n === undefined;
  const target = whole ? document.body : (blocks[n] || {}).e;
  if (!target) return null;

  // ---- CSS: the rules that apply to the exported elements
  const PSEUDO = /::?(?:before|after|hover|focus-visible|focus-within|focus|active|visited|link|placeholder|selection|first-line|first-letter|marker|backdrop|checked|disabled|enabled|invalid|valid|target|placeholder-shown|-webkit-[\w-]+|-moz-[\w-]+|-ms-[\w-]+)(?:\([^)]*\))?/g;
  const used = sel => sel.split(',').some(part => {
    const s = part.replace(PSEUDO, '').trim();
    if (!s || /^(html|body|:root|\*)(\s|$|[.:#\[>~+])/.test(s) || s === '*') return true;
    try { return target.matches(s) || !!target.querySelector(s); } catch (e) { return false; }
  });
  // cssText keeps shorthands (margin: 0) where the longhand list would spell out every side
  const decls = st => st.cssText.split(/;\s*(?=-{0,2}[a-zA-Z][\w-]*\s*:)/).map(d => d.trim().replace(/;$/, ''))
    .filter(Boolean).map(d => d + ';');
  const fonts = new Set(), anims = new Set(), faces = [], frames = {};
  const note = st => {
    const ff = st.getPropertyValue('font-family');
    if (ff) ff.split(',').forEach(f => fonts.add(f.trim().replace(/["']/g, '').toLowerCase()));
    ['animation-name', 'animation'].forEach(p => { const v = st.getPropertyValue(p); if (v) v.split(/[\s,]+/).forEach(a => anims.add(a)); });
  };
  const walk = (rules, ind) => { let out = '';
    for (const r of rules) {
      if (r instanceof CSSStyleRule) {
        if (used(r.selectorText)) { const d = decls(r.style);
          if (d.length) { out += `${ind}${r.selectorText} {\n${d.map(x => ind + '  ' + x).join('\n')}\n${ind}}\n\n`; note(r.style); } }
      } else if (r instanceof CSSMediaRule) {
        const inner = walk(r.cssRules, ind + '  '); if (inner) out += `${ind}@media ${r.media.mediaText} {\n${inner}${ind}}\n\n`;
      } else if (window.CSSSupportsRule && r instanceof CSSSupportsRule) {
        const inner = walk(r.cssRules, ind + '  '); if (inner) out += `${ind}@supports ${r.conditionText} {\n${inner}${ind}}\n\n`;
      } else if (r instanceof CSSFontFaceRule) { faces.push(r);
      } else if (r instanceof CSSKeyframesRule) { frames[r.name] = r;
      } else if (r.cssRules) { out += walk(r.cssRules, ind); }  // @layer, @container: flattened
    }
    return out; };
  let rulesCss = '';
  for (const sh of document.styleSheets) { try { rulesCss += walk(sh.cssRules, ''); } catch (e) {} }
  let head = '';
  for (const f of faces) {
    const fam = f.style.getPropertyValue('font-family').replace(/["']/g, '').trim().toLowerCase();
    if (fonts.has(fam)) head += `@font-face {\n${decls(f.style).map(x => '  ' + x).join('\n')}\n}\n\n`;
  }
  for (const [name, k] of Object.entries(frames)) if (anims.has(name))
    head += `@keyframes ${name} {\n` + [...k.cssRules].map(f => `  ${f.keyText} {\n${decls(f.style).map(x => '    ' + x).join('\n')}\n  }`).join('\n') + '\n}\n\n';

  // ---- HTML: a cleaned copy of the rendered elements
  const srcOf = new Map();  // the browser already picked the right image (lazy loading, srcset)
  [target, ...target.querySelectorAll('img')].forEach(img => { if (img.tagName === 'IMG' && img.currentSrc) srcOf.set(img, img.currentSrc); });
  const clone = target.cloneNode(true);
  const liveImgs = [target, ...target.querySelectorAll('*')], cloneEls = [clone, ...clone.querySelectorAll('*')];
  cloneEls.forEach((c, i) => { const live = liveImgs[i]; if (live && srcOf.has(live) && !c.getAttribute('src')) c.setAttribute('src', srcOf.get(live)); });
  clone.querySelectorAll('script, noscript, template, style, link[rel=preload], link[rel=modulepreload], link[rel=prefetch]').forEach(e => e.remove());
  const tw = document.createTreeWalker(clone, NodeFilter.SHOW_COMMENT), comments = [];
  while (tw.nextNode()) comments.push(tw.currentNode);
  comments.forEach(c => c.remove());
  const ANIM = /^(transform|translate|rotate|scale|opacity|will-change|transition|transition-[\w-]+|visibility|clip-path|filter)$/;
  for (const el of [clone, ...clone.querySelectorAll('*')]) {
    for (const lazy of ['src', 'srcset']) {
      const v = el.getAttribute('data-' + lazy);
      if (v && !el.getAttribute(lazy)) el.setAttribute(lazy, v);
    }
    for (const a of [...el.attributes]) {
      const k = a.name;
      if (k.startsWith('on') || k.startsWith('data-') || k.startsWith('framer-') || k.startsWith('astro-') ||
          k.startsWith('wire:') || k.startsWith('x-') || k.startsWith('v-') || k.startsWith('ng-') || k === 'nonce' || k === 'integrity')
        el.removeAttribute(k);
    }
    if (el.style && el.style.length) {
      for (const p of [...el.style]) if (ANIM.test(p)) el.style.removeProperty(p);
      if (!el.style.length) el.removeAttribute('style');
    }
    if (el.getAttribute('class') === '') el.removeAttribute('class');
  }
  return {
    html: whole ? clone.innerHTML : clone.outerHTML,
    css: head + rulesCss,
    title: document.title,
    lang: document.documentElement.lang || 'en',
    bodyClass: whole ? document.body.className : '',
  };
}"""

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
INLINE = {"a", "abbr", "b", "bdi", "bdo", "br", "cite", "code", "data", "dfn", "em", "i", "kbd", "mark", "q", "s", "samp",
          "small", "span", "strong", "sub", "sup", "time", "u", "var", "wbr", "label"}
RAW = {"pre", "textarea"}


class _Node:
    __slots__ = ("tag", "attrs", "children")

    def __init__(self, tag, attrs):
        self.tag, self.attrs, self.children = tag, attrs, []


class _TreeBuilder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _Node(None, [])
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        n = _Node(tag, attrs)
        self.stack[-1].children.append(n)
        if tag not in VOID:
            self.stack.append(n)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].children.append(_Node(tag, attrs))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _tree(fragment):
    b = _TreeBuilder()
    b.feed(fragment)
    b.close()
    return b.root


def _text_only(node):
    return all(isinstance(c, str) or (c.tag in INLINE and _text_only(c)) for c in node.children)


# ---------------------------------------------------------------- HTML

def _attrs_html(attrs):
    out = []
    for k, v in attrs:
        if v is None:
            out.append(k)
        else:
            out.append(f'{k}="{htmlmod.escape(v, quote=True)}"')
    return (" " + " ".join(out)) if out else ""


def _inline_html(node):
    if isinstance(node, str):
        return htmlmod.escape(" ".join(node.split()) if node.strip() else " ", quote=False)
    inner = "".join(_inline_html(c) for c in node.children)
    if node.tag in VOID:
        return f"<{node.tag}{_attrs_html(node.attrs)}>"
    return f"<{node.tag}{_attrs_html(node.attrs)}>{inner.strip() if node.tag not in INLINE else inner}</{node.tag}>"


def pretty_html(fragment, indent=0):
    lines = []

    def emit(node, depth):
        pad = "  " * depth
        if isinstance(node, str):
            t = " ".join(node.split())
            if t:
                lines.append(pad + htmlmod.escape(t, quote=False))
            return
        if node.tag in VOID:
            lines.append(f"{pad}<{node.tag}{_attrs_html(node.attrs)}>")
            return
        if node.tag in RAW:
            lines.append(pad + f"<{node.tag}{_attrs_html(node.attrs)}>" +
                         "".join(c if isinstance(c, str) else _inline_html(c) for c in node.children) + f"</{node.tag}>")
            return
        if node.tag == "svg" or (_text_only(node) and len(_inline_html(node)) <= 140):
            lines.append(pad + re.sub(r"\s+", " ", _inline_html(node)).strip())
            return
        lines.append(f"{pad}<{node.tag}{_attrs_html(node.attrs)}>")
        for c in node.children:
            emit(c, depth + 1)
        lines.append(f"{pad}</{node.tag}>")

    for c in _tree(fragment).children:
        emit(c, indent)
    return "\n".join(lines)


# ---------------------------------------------------------------- React (JSX)

JSX_ATTR = {
    "class": "className", "for": "htmlFor", "tabindex": "tabIndex", "readonly": "readOnly", "maxlength": "maxLength",
    "minlength": "minLength", "colspan": "colSpan", "rowspan": "rowSpan", "srcset": "srcSet", "crossorigin": "crossOrigin",
    "autoplay": "autoPlay", "playsinline": "playsInline", "frameborder": "frameBorder", "allowfullscreen": "allowFullScreen",
    "autocomplete": "autoComplete", "autofocus": "autoFocus", "enctype": "encType", "novalidate": "noValidate",
    "contenteditable": "contentEditable", "spellcheck": "spellCheck", "usemap": "useMap", "datetime": "dateTime",
    "accesskey": "accessKey", "referrerpolicy": "referrerPolicy", "fetchpriority": "fetchPriority", "inputmode": "inputMode",
    "enterkeyhint": "enterKeyHint", "http-equiv": "httpEquiv", "accept-charset": "acceptCharset", "itemprop": "itemProp",
    "itemscope": "itemScope", "itemtype": "itemType", "charset": "charSet", "cellpadding": "cellPadding",
    "cellspacing": "cellSpacing", "formaction": "formAction", "novalidate": "noValidate", "xlink:href": "xlinkHref",
    "xml:space": "xmlSpace", "xmlns:xlink": "xmlnsXlink",
    # SVG attributes the HTML parser lowercased
    "viewbox": "viewBox", "preserveaspectratio": "preserveAspectRatio", "gradientunits": "gradientUnits",
    "gradienttransform": "gradientTransform", "patternunits": "patternUnits", "patterncontentunits": "patternContentUnits",
    "patterntransform": "patternTransform", "clippathunits": "clipPathUnits", "maskunits": "maskUnits",
    "maskcontentunits": "maskContentUnits", "filterunits": "filterUnits", "primitiveunits": "primitiveUnits",
    "stddeviation": "stdDeviation", "basefrequency": "baseFrequency", "numoctaves": "numOctaves", "kernelmatrix": "kernelMatrix",
    "refx": "refX", "refy": "refY", "markerwidth": "markerWidth", "markerheight": "markerHeight", "markerunits": "markerUnits",
    "textlength": "textLength", "lengthadjust": "lengthAdjust", "spreadmethod": "spreadMethod", "startoffset": "startOffset",
    "tablevalues": "tableValues", "xchannelselector": "xChannelSelector", "ychannelselector": "yChannelSelector",
    "diffuseconstant": "diffuseConstant", "specularexponent": "specularExponent", "surfacescale": "surfaceScale",
    "pathlength": "pathLength", "attributename": "attributeName", "repeatcount": "repeatCount", "keytimes": "keyTimes",
    "keysplines": "keySplines", "calcmode": "calcMode", "pointsatx": "pointsAtX", "pointsaty": "pointsAtY",
    "pointsatz": "pointsAtZ", "limitingconeangle": "limitingConeAngle",
}
JSX_TAG = {"lineargradient": "linearGradient", "radialgradient": "radialGradient", "clippath": "clipPath",
           "foreignobject": "foreignObject", "textpath": "textPath", "fegaussianblur": "feGaussianBlur",
           "feoffset": "feOffset", "fecolormatrix": "feColorMatrix", "feblend": "feBlend", "femerge": "feMerge",
           "femergenode": "feMergeNode", "feflood": "feFlood", "fecomposite": "feComposite", "feturbulence": "feTurbulence",
           "fedisplacementmap": "feDisplacementMap", "fedropshadow": "feDropShadow", "animatetransform": "animateTransform"}
URL_ATTRS = {"src", "href", "poster", "srcset"}


def _camel(name):
    return re.sub(r"[-:]([a-z])", lambda m: m.group(1).upper(), name)


def _style_obj(css):
    parts = []
    for decl in css.split(";"):
        if ":" not in decl:
            continue
        k, v = decl.split(":", 1)
        k, v = k.strip(), v.strip()
        if not k:
            continue
        key = json.dumps(k) if k.startswith("--") else _camel(k.lower())
        parts.append(f"{key}: {json.dumps(v)}")
    return "{{ " + ", ".join(parts) + " }}"


def _jsx_url(v, absolute_assets):
    if not absolute_assets:
        return v
    def one(u):
        if not u or re.match(r"^([a-z][\w+.-]*:|/|#|\.\.)", u, re.I):
            return u
        return "/" + u
    if " " in v.strip() or "," in v:
        return ", ".join(" ".join([one(c.strip().split(" ")[0])] + c.strip().split(" ")[1:]) for c in v.split(",") if c.strip())
    return one(v)


def _jsx_attrs(tag, attrs, absolute_assets):
    out = []
    for k, v in attrs:
        if k == "style":
            if v and v.strip():
                out.append(f"style={_style_obj(v)}")
            continue
        if tag in ("input", "textarea", "select") and k == "value":
            k = "defaultValue"
        if tag == "input" and k == "checked":
            k = "defaultChecked"
        name = JSX_ATTR.get(k) or (k if k.startswith(("data-", "aria-")) else (_camel(k) if "-" in k or ":" in k else k))
        if v is None or (v == "" and k in ("hidden", "disabled", "required", "multiple", "selected", "allowfullscreen",
                                            "autoplay", "muted", "loop", "playsinline", "controls", "defer", "async",
                                            "readonly", "open", "novalidate", "itemscope", "checked", "autofocus")):
            out.append(name)
            continue
        if k in URL_ATTRS:
            v = _jsx_url(v, absolute_assets)
        out.append(f'{name}="{htmlmod.escape(v, quote=True)}"')
    return (" " + " ".join(out)) if out else ""


def _jsx_text(t):
    t = " ".join(t.split())
    return htmlmod.escape(t, quote=False).replace("{", "{'{'}").replace("}", "{'}'}")


def to_jsx(fragment, absolute_assets=True, indent=2):
    lines = []

    def inline(node):
        if isinstance(node, str):
            return _jsx_text(node) if node.strip() else " "
        tag = JSX_TAG.get(node.tag, node.tag)
        a = _jsx_attrs(node.tag, node.attrs, absolute_assets)
        if node.tag in VOID or not node.children:
            return f"<{tag}{a} />"
        return f"<{tag}{a}>" + "".join(inline(c) for c in node.children).strip() + f"</{tag}>"

    def emit(node, depth):
        pad = "  " * depth
        if isinstance(node, str):
            t = _jsx_text(node)
            if t:
                lines.append(pad + t)
            return
        tag = JSX_TAG.get(node.tag, node.tag)
        a = _jsx_attrs(node.tag, node.attrs, absolute_assets)
        if node.tag in VOID or not node.children:
            lines.append(f"{pad}<{tag}{a} />")
            return
        if node.tag == "svg" or (_text_only(node) and len(inline(node)) <= 140):
            lines.append(pad + re.sub(r"\s+", " ", inline(node)).strip())
            return
        lines.append(f"{pad}<{tag}{a}>")
        for c in node.children:
            emit(c, depth + 1)
        lines.append(f"{pad}</{tag}>")

    for c in _tree(fragment).children:
        emit(c, indent)
    return "\n".join(lines)


def react_component(name, fragment, css_import="./styles.css"):
    body = to_jsx(fragment, absolute_assets=True, indent=3)
    return (f'import "{css_import}";\n\n'
            f"export default function {name}() {{\n"
            f"  return (\n    <>\n{body}\n    </>\n  );\n}}\n")


def component_name(text, fallback="Page"):
    words = re.findall(r"[A-Za-z0-9]+", text or "")
    name = "".join(w[:1].upper() + w[1:] for w in words[:4]) or fallback
    return name if name[0].isalpha() else fallback + name
