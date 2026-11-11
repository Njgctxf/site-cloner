/* blackhole.js - Standalone WebGL raymarched Black Hole + inward StarField extracted from Reflex AI */
(() => {
  const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));
  const DEG2RAD = Math.PI / 180;

  function parseHex(hex) {
    const h = String(hex || "").replace("#", "").trim();
    const full = h.length === 3 ? h.split("").map(c => c + c).join("") : h;
    const n = parseInt(full.slice(0, 6), 16);
    if (isNaN(n)) return [255, 255, 255];
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function srgbToLinear(hex) {
    const [r, g, b] = parseHex(hex);
    const f = v => {
      const c = clamp(v / 255, 0, 1);
      return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    };
    return [f(r), f(g), f(b)];
  }
  function linearRgb(hex) {
    const [r, g, b] = parseHex(hex);
    return [clamp(r / 255, 0, 1), clamp(g / 255, 0, 1), clamp(b / 255, 0, 1)];
  }
  function normShift(hex) {
    const c = srgbToLinear(hex);
    const lum = 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    if (lum < 1e-4) return [1, 1, 1];
    const n = [c[0] / lum, c[1] / lum, c[2] / lum];
    const mx = Math.max(n[0], n[1], n[2]);
    if (mx <= 3) return n;
    const k = 2 / (mx - 1);
    return [1 + (n[0] - 1) * k, 1 + (n[1] - 1) * k, 1 + (n[2] - 1) * k];
  }

  /* ---------------- Inward StarField (canvas 2D) ---------------- */
  window.initReflexStars = function initReflexStars(canvas) {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let seed = 1597463007;
    const rand = () => {
      seed = (seed + 1831565813) >>> 0;
      let t = seed;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };

    const rayEdge = ang => {
      const c = Math.abs(Math.cos(ang)), s = Math.abs(Math.sin(ang));
      return Math.min(c > 1e-6 ? 0.5 / c : Infinity, s > 1e-6 ? 0.5 / s : Infinity);
    };

    let w = 0, h = 0, dpr = 1, stars = [], shooting = [];
    let tAcc = 0, lastT = 0, nextShoot = 2 + Math.random() * 3, raf = 0;

    function buildStars() {
      const count = Math.min(1800, Math.round(clamp(w * h / 10000 * (69 * 0.24), 40, 1200)));
      stars = [];
      for (let i = 0; i < count; i++) {
        const sx = rand(), sy = rand(), p = rand(), ph = rand() * Math.PI * 2;
        const z = Math.pow(rand(), 2.05);
        const dx = sx - 0.5, dy = sy - 0.5, dist = Math.hypot(dx, dy);
        const flowAngle = dist > 0.035 ? Math.atan2(dy, dx) : rand() * Math.PI * 2;
        stars.push({
          z,
          size: 0.5 + 1.5 * (0.12 * rand() + 0.88 * z),
          alpha: clamp(0.2 + 0.8 * Math.pow(z, 0.55) * (0.65 + 0.35 * rand()), 0, 1),
          tw: p < 0.22 ? 0.55 + p * 1.5 : 0.12 + p * 0.35,
          tf: 0.45 + rand() * 1.35,
          ph,
          accent: rand() * 100 < 10,
          flowAngle,
          flowSpeed: 0.72 + 0.56 * p,
          flowPhase: rand(),
        });
      }
    }

    function spawnMeteor() {
      const dir = Math.random() < 0.5 ? 1 : -1;
      const ang = ((dir > 0 ? 24 : 156) + (Math.random() * 14 - 7)) * DEG2RAD;
      const dist = Math.min(w, h) * (0.35 + Math.random() * 0.3) + 120;
      const speed = 620 + Math.random() * 420;
      shooting.push({
        x: dir > 0 ? w * (0.05 + Math.random() * 0.55) : w * (0.4 + Math.random() * 0.55),
        y: h * (0.04 + Math.random() * 0.38),
        dx: Math.cos(ang),
        dy: Math.sin(ang),
        speed,
        len: 90 + Math.random() * 140,
        life: dist / speed,
        age: 0,
      });
    }

    function resize() {
      const rect = canvas.parentElement.getBoundingClientRect();
      const nw = Math.max(1, Math.round(rect.width));
      const nh = Math.max(1, Math.round(rect.height));
      const nd = clamp(window.devicePixelRatio || 1, 1, 2);
      if (nw === w && nh === h && nd === dpr && stars.length) return;
      w = nw; h = nh; dpr = nd;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      buildStars();
    }

    function frame(now) {
      raf = 0;
      if (document.hidden) return;
      const dt = lastT ? clamp((now - lastT) / 1000, 0, 0.05) : 0.016;
      lastT = now;
      tAcc += dt;

      nextShoot -= dt;
      if (nextShoot <= 0) {
        spawnMeteor();
        nextShoot = Math.max(1.5, -Math.log(1 - Math.random()) * 11);
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);

      const minSide = Math.max(1, Math.min(w, h));
      for (let i = 0; i < stars.length; i++) {
        const s = stars[i];
        const rate = 28 / minSide * (0.72 + s.flowSpeed * 0.44);
        const cyc = ((tAcc * rate + s.flowPhase) % 1 + 1) % 1;
        const rMax = rayEdge(s.flowAngle);
        const rad = rMax * 1.08 * (1 - cyc);
        const x = (0.5 + Math.cos(s.flowAngle) * rad) * w;
        const y = (0.5 + Math.sin(s.flowAngle) * rad) * h;
        const tw = 0.5 + 0.5 * Math.sin(tAcc * s.tf * 2.5 + s.ph);
        const alpha = s.alpha * (1 - clamp(s.tw, 0, 0.9) * tw);
        if (alpha < 0.015) continue;

        ctx.globalAlpha = alpha;
        ctx.fillStyle = s.accent ? "#c2b2ff" : "#ffffff";
        ctx.beginPath();
        ctx.arc(x, y, s.size * 0.9, 0, Math.PI * 2);
        ctx.fill();
      }

      if (shooting.length) {
        ctx.globalCompositeOperation = "lighter";
        ctx.lineCap = "round";
        for (const m of shooting) {
          m.age += dt;
          const p = clamp(m.age / m.life, 0, 1);
          const env = Math.sin(Math.PI * p);
          const x = m.x + m.dx * m.speed * m.age;
          const y = m.y + m.dy * m.speed * m.age;
          const len = m.len * (0.35 + 0.65 * env);
          const tx = x - m.dx * len, ty = y - m.dy * len;
          const g = ctx.createLinearGradient(tx, ty, x, y);
          g.addColorStop(0, "rgba(194,178,255,0)");
          g.addColorStop(0.6, `rgba(194,178,255,${0.3 * env})`);
          g.addColorStop(1, `rgba(255,255,255,${0.9 * env})`);
          ctx.globalAlpha = 1;
          ctx.strokeStyle = g;
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.moveTo(tx, ty);
          ctx.lineTo(x, y);
          ctx.stroke();
        }
        ctx.globalCompositeOperation = "source-over";
        shooting = shooting.filter(m => m.age < m.life);
      }

      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(frame);
    }

    const ro = new ResizeObserver(resize);
    ro.observe(canvas.parentElement);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !raf) { lastT = 0; raf = requestAnimationFrame(frame); }
    });
    resize();
    raf = requestAnimationFrame(frame);
  };

  /* ---------------- WebGL Schwarzschild Black Hole ---------------- */
  window.initReflexBlackHole = function initReflexBlackHole(canvas, opts = {}) {
    if (!canvas) return false;
    const cfg = {
      distance: window.innerWidth < 810 ? 50 : 39.5,
      elevation: -4,
      azimuth: 0,
      roll: 0,
      fieldOfView: window.innerWidth < 810 ? 28 : 34,
      focusX: 0.5,
      focusY: window.innerWidth < 810 ? 0.55 : 0.56,
      diskInner: 3.0,
      diskOuter: 10.8,
      diskThickness: 0.26,
      diskDensity: 1.0,
      brightness: 0.85,
      spinSpeed: 0.045,
      grain: 0.26,
      doppler: 0.35,
      hotColor: "#f4f0ff",
      midColor: "#8a72ff",
      coolColor: "#2a1470",
      blueshift: "#8fc2ff",
      redshift: "#e08cff",
      glow: 1.05,
      exposure: 1.18,
      vignette: 0.0,
      backgroundColor: "#040014",
      shadowColor: "#040014",
      steps: 230,
      resolution: 0.58,
      maxDpr: 1.5,
      ...opts,
    };

    const glOpts = {
      alpha: true,
      premultipliedAlpha: true,
      antialias: false,
      depth: false,
      stencil: false,
      powerPreference: "high-performance",
    };
    let gl = null;
    try {
      gl = canvas.getContext("webgl2", glOpts) || canvas.getContext("webgl", glOpts);
    } catch {
      gl = null;
    }
    if (!gl) return false;

    const isWebGL2 = typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    const renderer = dbg ? String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "") : "";
    const isSoftware = /swiftshader|llvmpipe|softpipe|software|microsoft basic/i.test(renderer);

    const VS = `
attribute vec2 aPos;
varying vec2 vUv;
void main() {
  vUv = aPos * 0.5 + 0.5;
  gl_Position = vec4(aPos, 0.0, 1.0);
}`;

    const FS_MARCH = `
precision highp float;
#define MAX_STEPS 360
#define WIND_CYCLE 46.0
#define CRIT_H2 6.75

varying vec2 vUv;
uniform vec2 uRes;
uniform float uTime;
uniform vec3 uCamPos, uRight, uUp, uFwd;
uniform float uTanHalf;
uniform vec2 uFocus;
uniform float uSteps, uSkyR, uReach, uDiskIn, uDiskOut, uThick, uDensity;
uniform float uSpin, uGrain, uBright, uDoppler;
uniform vec3 uHot, uMid, uCool, uBlue, uRed;
uniform float uEncode;
uniform vec2 uJitter;
uniform float uSeed;

float hash13(vec3 p) {
  p = fract(p * 0.3183099 + vec3(0.1, 0.2, 0.3));
  p *= 17.0;
  return fract(p.x * p.y * p.z * (p.x + p.y + p.z));
}

float vnoise(vec3 x) {
  vec3 i = floor(x), f = fract(x);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(mix(hash13(i), hash13(i + vec3(1,0,0)), f.x), mix(hash13(i + vec3(0,1,0)), hash13(i + vec3(1,1,0)), f.x), f.y),
    mix(mix(hash13(i + vec3(0,0,1)), hash13(i + vec3(1,0,1)), f.x), mix(hash13(i + vec3(0,1,1)), hash13(i + vec3(1,1,1)), f.x), f.y),
    f.z
  );
}

float fbm(vec3 p, float lod) {
  float a = 0.5, s = 0.0;
  for (int i = 0; i < 4; i++) {
    s += (i == 3 ? a * lod : a) * vnoise(p);
    p = p * 2.03 + vec3(11.3, 7.1, 3.7);
    a *= 0.5;
  }
  return s;
}

void gasAt(vec3 p, float rd, float dt, out float dens, out vec3 tint, out float heat) {
  float rn = clamp((rd - uDiskIn) / max(0.001, uDiskOut - uDiskIn), 0.0, 1.0);
  float tk = uThick * (0.35 + 1.25 * rn);
  float v = p.y / tk;
  float sheet = exp(-v * v);
  float lod = clamp(1.0 - dt * uGrain * 14.0, 0.0, 1.0);
  float phi = atan(p.z, p.x);
  float omega = uSpin * pow(uDiskIn / rd, 1.5);
  float lr = log(rd) * 1.1 + uSpin * uTime * 0.05;

  float u = uTime / WIND_CYCLE;
  float fA = fract(u), fB = fract(u + 0.5);
  float w = abs(2.0 * fA - 1.0);
  float cA = fbm(vec3(vec2(cos(phi + omega * fA * WIND_CYCLE), sin(phi + omega * fA * WIND_CYCLE)) * (rd * uGrain), lr), lod);
  float cB = fbm(vec3(vec2(cos(phi + omega * fB * WIND_CYCLE), sin(phi + omega * fB * WIND_CYCLE)) * (rd * uGrain), lr + 40.0), lod);
  float clouds = mix(cA, cB, w);
  float filaments = clouds * clouds * 1.75;

  float prof = smoothstep(0.0, 0.07, rn) * (1.0 - smoothstep(0.45, 1.0, rn)) * pow(uDiskIn / rd, 2.0);
  dens = max(0.0, filaments * 1.5 - 0.30) * sheet * prof * uDensity * 4.6;
  heat = pow(uDiskIn / rd, 0.8) * (0.72 + 0.55 * clouds);
  tint = mix(uCool, uMid, smoothstep(0.10, 0.52, heat));
  tint = mix(tint, uHot, smoothstep(0.52, 1.05, heat));
}

void main() {
  vec2 uv = (gl_FragCoord.xy + uJitter - uFocus * uRes) / min(uRes.x, uRes.y);
  vec3 dir = normalize(uFwd + (uv.x * uRight + uv.y * uUp) * 2.0 * uTanHalf);
  vec3 pos = uCamPos, vel = dir;
  vec3 hv = cross(pos, vel);
  float h2 = dot(hv, hv), h = sqrt(h2);
  if (h > uReach) { gl_FragColor = vec4(0.0); return; }

  float swept = 0.0, transmit = 1.0;
  vec3 col = vec3(0.0);
  bool captured = false, escaped = false;
  float jitter = fract(sin(dot(gl_FragCoord.xy + uSeed, vec2(12.9898, 78.233))) * 43758.5453);

  for (int i = 0; i < MAX_STEPS; i++) {
    if (float(i) >= uSteps) break;
    float r2 = dot(pos, pos), r = sqrt(r2);
    if (r < 1.0) { captured = true; break; }
    if (r > uSkyR && dot(pos, vel) > 0.0) { escaped = true; break; }
    if (transmit < 0.004) break;

    float dt = clamp(0.14 * (r - 1.0), 0.025, 1.1);
    if (r < uDiskOut * 1.25) {
      float rn = clamp((r - uDiskIn) / max(0.001, uDiskOut - uDiskIn), 0.0, 1.0);
      float tk = uThick * (0.35 + 1.25 * rn);
      dt = min(dt, max(tk * 0.38, abs(pos.y) * 0.5));
    }
    swept += h * dt / r2;
    float deep = exp(-1.3 * max(0.0, swept - 4.6));
    jitter = fract(jitter + 0.6180339887);
    vec3 mid = pos + vel * (dt * jitter);
    float rd = length(mid.xz);

    if (rd > uDiskIn && rd < uDiskOut && abs(mid.y) < uThick * 5.0) {
      float dens, heat; vec3 tint;
      gasAt(mid, rd, dt, dens, tint, heat);
      if (dens > 0.001) {
        vec3 tang = normalize(cross(vec3(0.0, 1.0, 0.0), vec3(mid.x, 0.0, mid.z)));
        float beta = min(0.85, sqrt(0.5 / max(rd, 1.5)));
        float gam = inversesqrt(max(1e-4, 1.0 - beta * beta));
        vec3 toObs = -vel;
        float g = 1.0 / (gam * (1.0 - beta * dot(tang, toObs)));
        g *= sqrt(max(0.05, 1.0 - 1.0 / rd));
        float boost = pow(max(g, 0.02), 3.0 * uDoppler);
        vec3 shift = mix(vec3(1.0), g > 1.0 ? uBlue : uRed, clamp(abs(g - 1.0) * 1.6, 0.0, 1.0) * uDoppler);
        float emit = uBright * (0.26 + 2.0 * heat * heat);
        col += tint * shift * (emit * boost * dens * transmit * dt * deep);
        transmit *= exp(-dens * 0.30 * dt);
      }
    }
    vel += (-1.5 * h2 * pos / (r2 * r2 * r)) * dt;
    pos += vel * dt;
  }

  float cover = (captured || (!escaped && h2 < CRIT_H2 && dot(pos, vel) < 0.0)) ? 1.0 : 1.0 - transmit;
  if (uEncode > 0.5) col = sqrt(col / (1.0 + col));
  gl_FragColor = vec4(col, cover);
}`;

    const FS_ACCUM = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uCur, uPrev;
uniform float uAlpha, uDecode;
void main() {
  vec4 c = texture2D(uCur, vUv), p = texture2D(uPrev, vUv);
  gl_FragColor = uDecode > 0.5
    ? vec4(sqrt(mix(p.rgb * p.rgb, c.rgb * c.rgb, uAlpha)), mix(p.a, c.a, uAlpha))
    : mix(p, c, uAlpha);
}`;

    const FS_BRIGHT = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uTex;
uniform vec2 uTexel;
uniform float uDecode, uPack, uThreshold;
vec3 tap(vec2 o) {
  vec3 t = texture2D(uTex, vUv + uTexel * o).rgb;
  return uDecode > 0.5 ? t * t : t;
}
void main() {
  vec3 s = (tap(vec2(-1,-1)) + tap(vec2(1,-1)) + tap(vec2(-1,1)) + tap(vec2(1,1))) * 0.25;
  if (uDecode > 0.5) s = s / max(vec3(0.002), 1.0 - s);
  float l = max(s.r, max(s.g, s.b));
  s *= max(0.0, l - uThreshold) / max(0.0001, l);
  gl_FragColor = vec4(uDecode > 0.5 ? sqrt(s * uPack) : s * uPack, 1.0);
}`;

    const FS_BLUR = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uTex;
uniform vec2 uStep;
uniform float uDecode;
vec3 tap(vec2 uv) {
  vec3 t = texture2D(uTex, uv).rgb;
  return uDecode > 0.5 ? t * t : t;
}
void main() {
  vec3 s = tap(vUv) * 0.2270270;
  s += (tap(vUv + uStep * 1.3846154) + tap(vUv - uStep * 1.3846154)) * 0.3162162;
  s += (tap(vUv + uStep * 3.2307692) + tap(vUv - uStep * 3.2307692)) * 0.0702702;
  gl_FragColor = vec4(uDecode > 0.5 ? sqrt(s) : s, 1.0);
}`;

    const FS_COMP = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uScene, uBloom;
uniform float uDecode, uPack, uGlow, uExposure, uVignette, uSeed;
uniform vec3 uShadow;
vec3 aces(vec3 x) { return clamp((x * (2.51 * x + 0.03)) / (x * (2.43 * x + 0.59) + 0.14), 0.0, 1.0); }
float peak(vec3 v) { return max(v.r, max(v.g, v.b)); }
void main() {
  vec4 sc = texture2D(uScene, vUv);
  vec3 scene = sc.rgb;
  if (uDecode > 0.5) { scene = scene * scene; scene = scene / max(vec3(0.002), 1.0 - scene); }
  vec3 b = texture2D(uBloom, vUv).rgb;
  vec3 bloom = (uDecode > 0.5 ? b * b : b) / uPack;
  vec3 light = (scene + bloom * uGlow) * uExposure;
  vec2 d = vUv - 0.5;
  float veil = max(1.0 - uVignette * dot(d, d) * 1.9, 0.0);
  vec3 c = pow(aces(light), vec3(0.4545));
  vec3 hue = pow(aces(light * veil), vec3(0.4545));
  c = hue * (peak(c) * veil / max(peak(hue), 1e-5));
  float aL = peak(c);
  float s = sc.a;
  float a = aL + s * (1.0 - aL);
  vec3 rgb = c + uShadow * (s * (1.0 - aL));
  float n = fract(sin(dot(gl_FragCoord.xy + uSeed, vec2(12.9898, 78.233))) * 43758.5453);
  float dz = a >= 1.0 / 255.0 ? (n - 0.5) / 255.0 : 0.0;
  rgb += dz;
  a = clamp(a + dz, 0.0, 1.0);
  gl_FragColor = vec4(clamp(rgb, 0.0, a), a);
}`;

    function compile(type, src) {
      const sh = gl.createShader(type);
      gl.shaderSource(sh, src);
      gl.compileShader(sh);
      if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
        gl.deleteShader(sh);
        return null;
      }
      return sh;
    }
    function buildProg(fsSrc) {
      const vs = compile(gl.VERTEX_SHADER, VS), fs = compile(gl.FRAGMENT_SHADER, fsSrc);
      if (!vs || !fs) return null;
      const p = gl.createProgram();
      gl.attachShader(p, vs); gl.attachShader(p, fs);
      gl.bindAttribLocation(p, 0, "aPos");
      gl.linkProgram(p);
      gl.deleteShader(vs); gl.deleteShader(fs);
      if (!gl.getProgramParameter(p, gl.LINK_STATUS)) return null;
      const u = {};
      const n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
      for (let i = 0; i < n; i++) {
        const info = gl.getActiveUniform(p, i);
        if (info) u[info.name] = gl.getUniformLocation(p, info.name);
      }
      return { p, u };
    }

    const pMarch = buildProg(FS_MARCH), pAccum = buildProg(FS_ACCUM), pBright = buildProg(FS_BRIGHT),
          pBlur = buildProg(FS_BLUR), pComp = buildProg(FS_COMP);
    if (!pMarch || !pAccum || !pBright || !pBlur || !pComp) return false;

    const vbo = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, vbo);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.disable(gl.DEPTH_TEST);
    gl.disable(gl.BLEND);

    let useHalf = true, texType = gl.UNSIGNED_BYTE, texFormat = gl.RGBA, texFilter = gl.LINEAR, pack = 1;
    if (isWebGL2 && (gl.getExtension("EXT_color_buffer_half_float") || gl.getExtension("EXT_color_buffer_float"))) {
      texType = gl.HALF_FLOAT; texFormat = gl.RGBA16F;
    } else if (!isWebGL2 && gl.getExtension("OES_texture_half_float") && gl.getExtension("EXT_color_buffer_half_float")) {
      texType = gl.getExtension("OES_texture_half_float").HALF_FLOAT_OES;
      texFilter = gl.getExtension("OES_texture_half_float_linear") ? gl.LINEAR : gl.NEAREST;
    } else {
      useHalf = false; pack = 0.12;
    }

    function makeTarget(w, h) {
      const tex = gl.createTexture(), fb = gl.createFramebuffer();
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.texImage2D(gl.TEXTURE_2D, 0, texFormat, w, h, 0, gl.RGBA, texType, null);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, texFilter);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, texFilter);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
      gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
      gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
      const ok = gl.checkFramebufferStatus(gl.FRAMEBUFFER) === gl.FRAMEBUFFER_COMPLETE;
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      if (!ok) { gl.deleteTexture(tex); gl.deleteFramebuffer(fb); return null; }
      return { fb, tex, w, h };
    }

    let rtCur = null, rtPrev = null, rtNext = null, rtB0 = null, rtB1 = null;
    let cw = 0, ch = 0, frameIdx = 0;

    function allocTargets() {
      const rect = canvas.parentElement.getBoundingClientRect();
      const dpr = isSoftware ? 1 : Math.min(window.devicePixelRatio || 1, cfg.maxDpr);
      const scale = isSoftware ? 0.34 : cfg.resolution;
      const w = Math.max(2, Math.round(rect.width * dpr));
      const h = Math.max(2, Math.round(rect.height * dpr));
      if (w === cw && h === ch && rtCur) return;
      [rtCur, rtPrev, rtNext, rtB0, rtB1].forEach(t => { if (t) { gl.deleteTexture(t.tex); gl.deleteFramebuffer(t.fb); } });
      cw = w; ch = h; canvas.width = w; canvas.height = h;
      const rw = Math.max(2, Math.round(w * scale)), rh = Math.max(2, Math.round(h * scale));
      rtCur = makeTarget(rw, rh); rtPrev = makeTarget(rw, rh); rtNext = makeTarget(rw, rh);
      if (!rtCur && useHalf) {
        useHalf = false; texType = gl.UNSIGNED_BYTE; texFormat = gl.RGBA; texFilter = gl.LINEAR; pack = 0.12;
        rtCur = makeTarget(rw, rh); rtPrev = makeTarget(rw, rh); rtNext = makeTarget(rw, rh);
      }
      const bw = Math.max(2, rw >> 2), bh = Math.max(2, rh >> 2);
      rtB0 = makeTarget(bw, bh); rtB1 = makeTarget(bw, bh);
      frameIdx = 0;
    }

    const bindRT = (prog, rt) => {
      gl.useProgram(prog.p);
      gl.bindFramebuffer(gl.FRAMEBUFFER, rt ? rt.fb : null);
      gl.viewport(0, 0, rt ? rt.w : gl.drawingBufferWidth, rt ? rt.h : gl.drawingBufferHeight);
    };
    const bindTex = (tex, unit) => { gl.activeTexture(gl.TEXTURE0 + unit); gl.bindTexture(gl.TEXTURE_2D, tex); };

    const colors = {
      hot: srgbToLinear(cfg.hotColor),
      mid: srgbToLinear(cfg.midColor),
      cool: srgbToLinear(cfg.coolColor),
      blue: normShift(cfg.blueshift),
      red: normShift(cfg.redshift),
      shadow: linearRgb(cfg.shadowColor),
    };
    const jit = [[.5, .333], [.25, .667], [.75, .111], [.125, .444], [.625, .778], [.375, .222], [.875, .556], [.0625, .889]];

    let tSim = 0, lastNow = 0, raf = 0;
    function step(now) {
      raf = 0;
      if (document.hidden || !rtCur || !rtB0) return;
      const dt = lastNow ? Math.min(0.05, (now - lastNow) / 1000) : 0.016;
      lastNow = now;
      tSim += dt;

      const az = cfg.azimuth * DEG2RAD, el = clamp(cfg.elevation, -88, 88) * DEG2RAD, dist = cfg.distance;
      const ce = Math.cos(el);
      const sx = dist * ce * Math.cos(az), sy = dist * Math.sin(el), sz = dist * ce * Math.sin(az);
      const fx = -sx / dist, fy = -sy / dist, fz = -sz / dist;
      let rx = fz, ry = 0, rz = -fx;
      const rlen = Math.hypot(rx, ry, rz) || 1;
      rx /= rlen; rz /= rlen;
      const ux = ry * fz - rz * fy, uy = rz * fx - rx * fz, uz = rx * fy - ry * fx;

      bindRT(pMarch, rtCur);
      const u = pMarch.u;
      gl.uniform2f(u.uRes, rtCur.w, rtCur.h);
      gl.uniform1f(u.uTime, tSim);
      gl.uniform3f(u.uCamPos, sx, sy, sz);
      gl.uniform3f(u.uRight, rx, ry, rz);
      gl.uniform3f(u.uUp, ux, uy, uz);
      gl.uniform3f(u.uFwd, fx, fy, fz);
      gl.uniform1f(u.uTanHalf, Math.tan(cfg.fieldOfView * 0.5 * DEG2RAD));
      gl.uniform2f(u.uFocus, cfg.focusX, 1 - cfg.focusY);
      gl.uniform1f(u.uSteps, isSoftware ? 110 : cfg.steps);
      gl.uniform1f(u.uSkyR, Math.max(dist * 1.35, cfg.diskOuter * 2.4));
      gl.uniform1f(u.uReach, Math.hypot(cfg.diskOuter, 5 * cfg.diskThickness) * 1.2 + 1);
      gl.uniform1f(u.uDiskIn, cfg.diskInner);
      gl.uniform1f(u.uDiskOut, cfg.diskOuter);
      gl.uniform1f(u.uThick, cfg.diskThickness);
      gl.uniform1f(u.uDensity, cfg.diskDensity);
      gl.uniform1f(u.uSpin, cfg.spinSpeed * Math.PI * 2);
      gl.uniform1f(u.uGrain, cfg.grain);
      gl.uniform1f(u.uBright, cfg.brightness);
      gl.uniform1f(u.uDoppler, cfg.doppler);
      gl.uniform3fv(u.uHot, colors.hot);
      gl.uniform3fv(u.uMid, colors.mid);
      gl.uniform3fv(u.uCool, colors.cool);
      gl.uniform3fv(u.uBlue, colors.blue);
      gl.uniform3fv(u.uRed, colors.red);
      gl.uniform1f(u.uEncode, useHalf ? 0 : 1);
      const j = jit[frameIdx % jit.length];
      gl.uniform2f(u.uJitter, j[0] - 0.5, j[1] - 0.5);
      gl.uniform1f(u.uSeed, (frameIdx % 64) * 17.13);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      bindRT(pAccum, rtNext);
      bindTex(rtCur.tex, 0); bindTex(rtPrev.tex, 1);
      gl.uniform1i(pAccum.u.uCur, 0); gl.uniform1i(pAccum.u.uPrev, 1);
      gl.uniform1f(pAccum.u.uAlpha, frameIdx === 0 ? 1 : 0.14);
      gl.uniform1f(pAccum.u.uDecode, useHalf ? 0 : 1);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      const tmp = rtPrev; rtPrev = rtNext; rtNext = tmp; frameIdx++;

      bindRT(pBright, rtB0);
      bindTex(rtPrev.tex, 0);
      gl.uniform1i(pBright.u.uTex, 0);
      gl.uniform2f(pBright.u.uTexel, 1 / rtPrev.w, 1 / rtPrev.h);
      gl.uniform1f(pBright.u.uDecode, useHalf ? 0 : 1);
      gl.uniform1f(pBright.u.uPack, pack);
      gl.uniform1f(pBright.u.uThreshold, 0.85);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      const blurPass = (src, dst, sx2, sy2) => {
        bindRT(pBlur, dst); bindTex(src.tex, 0);
        gl.uniform1i(pBlur.u.uTex, 0);
        gl.uniform2f(pBlur.u.uStep, sx2 / dst.w, sy2 / dst.h);
        gl.uniform1f(pBlur.u.uDecode, useHalf ? 0 : 1);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      };
      blurPass(rtB0, rtB1, 1, 0); blurPass(rtB1, rtB0, 0, 1);
      blurPass(rtB0, rtB1, 2.6, 0); blurPass(rtB1, rtB0, 0, 2.6);

      bindRT(pComp, null);
      bindTex(rtPrev.tex, 0); bindTex(rtB0.tex, 1);
      gl.uniform1i(pComp.u.uScene, 0); gl.uniform1i(pComp.u.uBloom, 1);
      gl.uniform1f(pComp.u.uDecode, useHalf ? 0 : 1);
      gl.uniform1f(pComp.u.uPack, pack);
      gl.uniform1f(pComp.u.uGlow, cfg.glow * 0.26);
      gl.uniform1f(pComp.u.uExposure, cfg.exposure);
      gl.uniform1f(pComp.u.uVignette, cfg.vignette);
      gl.uniform1f(pComp.u.uSeed, (tSim * 60) % 1000);
      gl.uniform3fv(pComp.u.uShadow, colors.shadow);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      raf = requestAnimationFrame(step);
    }

    const ro = new ResizeObserver(allocTargets);
    ro.observe(canvas.parentElement);
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && !raf) { lastNow = 0; raf = requestAnimationFrame(step); }
    });
    allocTargets();
    raf = requestAnimationFrame(step);
    return {
      ok: true,
      setColors(next = {}) {
        if (next.hotColor) colors.hot = srgbToLinear(next.hotColor);
        if (next.midColor) colors.mid = srgbToLinear(next.midColor);
        if (next.coolColor) colors.cool = srgbToLinear(next.coolColor);
        if (next.blueshift) colors.blue = normShift(next.blueshift);
        if (next.redshift) colors.red = normShift(next.redshift);
        if (next.shadowColor) colors.shadow = linearRgb(next.shadowColor);
        frameIdx = 0;
      }
    };
  };
})();
