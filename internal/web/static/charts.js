// Draws the dashboard's three charts from /stats.json. No library: three
// shapes, one axis each, drawn straight into the inline SVG the page ships.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const PAD = { l: 34, r: 6, t: 8, b: 16 };
  const SERIES = [
    { key: "authoritative", label: "Local", color: "--series-1" },
    { key: "forwarded", label: "Forwarded", color: "--series-2" },
    { key: "blocked", label: "Blocked", color: "--series-3" },
  ];

  const el = (name, attrs) => {
    const n = document.createElementNS(NS, name);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  };
  const hue = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

  // niceMax rounds the axis ceiling up to a 1/2/5 step, so the midpoint
  // gridline lands on a round number instead of being labelled 2 at 1.5.
  function niceMax(max) {
    if (!(max > 0)) return 1;
    const pow = Math.pow(10, Math.floor(Math.log10(max)));
    for (const step of [1, 2, 5, 10]) {
      if (max <= step * pow) return step * pow;
    }
    return 10 * pow;
  }

  // plot is the shared frame: it clears the svg, draws the y axis and its grid,
  // and hands back the functions that map a sample onto it.
  function plot(fig, max, suffix, exact) {
    const svg = fig.querySelector("svg");
    const [, , w, h] = svg.getAttribute("viewBox").split(" ").map(Number);
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    const top = exact ? max : niceMax(max);
    const x = (i, n) => PAD.l + (i * (w - PAD.l - PAD.r)) / Math.max(n - 1, 1);
    const y = (v) => h - PAD.b - (v / top) * (h - PAD.t - PAD.b);

    // A small axis rounds its midpoint onto a neighbour — 0, 1, 1 for a 1ms
    // ceiling. Two identical labels look like a rendering fault, so the
    // midpoint is dropped rather than repeated.
    const seen = new Set();
    for (const frac of [0, 0.5, 1]) {
      const yy = y(top * frac);
      svg.appendChild(el("line", { class: "gridline", x1: PAD.l, x2: w - PAD.r, y1: yy, y2: yy }));
      const label = Math.round(top * frac) + suffix;
      if (seen.has(label)) continue;
      seen.add(label);
      const t = el("text", { class: "axis", x: 0, y: yy + 3 });
      t.textContent = label;
      svg.appendChild(t);
    }
    return { svg, x, y, w, h };
  }

  // area draws one stacked band. The 2px gap between bands is a stroke in the
  // panel color, so touching fills stay legible instead of merging into a blob.
  function area(p, base, vals, color) {
    const n = vals.length;
    let top = "", bottom = "";
    for (let i = 0; i < n; i++) {
      top += `${i ? "L" : "M"}${p.x(i, n)},${p.y(base[i] + vals[i])}`;
    }
    for (let i = n - 1; i >= 0; i--) {
      bottom += `L${p.x(i, n)},${p.y(base[i])}`;
    }
    p.svg.appendChild(el("path", { d: top + bottom + "Z", fill: color, "fill-opacity": ".55" }));
    p.svg.appendChild(el("path", {
      d: top, fill: "none", stroke: color, "stroke-width": 2, "stroke-linejoin": "round",
    }));
  }

  // line draws a rate or an average. A null sample is a minute with nothing to
  // average, which breaks the path: drawing it as zero would claim a 0% hit
  // rate on a cache that was simply never asked.
  function line(p, vals, color) {
    const n = vals.length;
    let d = "", pen = false;
    for (let i = 0; i < n; i++) {
      if (vals[i] === null) {
        pen = false;
        continue;
      }
      d += `${pen ? "L" : "M"}${p.x(i, n)},${p.y(vals[i])}`;
      pen = true;
    }
    p.svg.appendChild(el("path", {
      d, fill: "none", stroke: color, "stroke-width": 2,
      "stroke-linejoin": "round", "stroke-linecap": "round",
    }));

    // A lone sample between two gaps is a path with nowhere to go, and an
    // invisible line is indistinguishable from a broken chart. Mark it.
    for (let i = 0; i < n; i++) {
      if (vals[i] === null) continue;
      const alone = (i === 0 || vals[i - 1] === null) && (i === n - 1 || vals[i + 1] === null);
      if (alone) {
        p.svg.appendChild(el("circle", { cx: p.x(i, n), cy: p.y(vals[i]), r: 3, fill: color }));
      }
    }
  }

  function drawQueries(fig, history) {
    const cols = SERIES.map((s) => history.map((b) => b[s.key] || 0));
    const totals = history.map((_, i) => cols.reduce((sum, c) => sum + c[i], 0));
    const p = plot(fig, Math.max(...totals), "");

    const base = history.map(() => 0);
    SERIES.forEach((s, si) => {
      area(p, base.slice(), cols[si], hue(s.color));
      for (let i = 0; i < base.length; i++) base[i] += cols[si][i];
    });

    // The legend totals the window, not the newest bucket: the current minute
    // is only partly elapsed, so it reads 0 for most of every minute.
    fig.querySelectorAll(".legend .key").forEach((k) => {
      const si = SERIES.findIndex((s) => s.key === k.dataset.series);
      k.querySelector("b").textContent = cols[si].reduce((a, b) => a + b, 0);
    });
    hover(fig, p, history, (b) => SERIES.map((s) => ({
      series: s.key, text: s.label + " " + (b[s.key] || 0),
    })));
  }

  function drawCache(fig, history) {
    const vals = history.map((b) => {
      const t = (b.cache_hits || 0) + (b.cache_misses || 0);
      return t ? Math.round((b.cache_hits * 100) / t) : null;
    });
    const p = plot(fig, 100, "%", true);
    line(p, vals, hue("--series-1"));
    hover(fig, p, history, (b, i) =>
      [{ text: vals[i] === null ? "no lookups" : vals[i] + "% hit rate" }]);
  }

  function drawLatency(fig, history) {
    const vals = history.map((b) =>
      (b.latency_count ? Math.round(b.latency_sum_ms / b.latency_count) : null));
    const p = plot(fig, Math.max(0, ...vals.filter((v) => v !== null)), "ms");
    line(p, vals, hue("--series-1"));
    hover(fig, p, history, (b, i) =>
      [{ text: vals[i] === null ? "no queries" : vals[i] + " ms average" }]);
  }

  // fillTip writes the tooltip as DOM nodes. rows carry text, never markup, so
  // nothing the endpoint returns is ever parsed as HTML.
  function fillTip(tip, when, rows) {
    tip.textContent = "";
    const head = document.createElement("b");
    head.textContent = when.getHours() + ":" + String(when.getMinutes()).padStart(2, "0");
    tip.appendChild(head);
    for (const r of rows) {
      tip.appendChild(document.createElement("br"));
      const span = document.createElement("span");
      if (r.series) {
        span.className = "k";
        span.dataset.series = r.series;
      }
      span.textContent = r.text;
      tip.appendChild(span);
    }
  }

  // hover adds the crosshair and tooltip. The hit target is the whole plot
  // area, not the 2px line, so a minute is readable without pixel hunting.
  function hover(fig, p, history, rowsFor) {
    const tip = fig.querySelector(".tip") || fig.appendChild(document.createElement("div"));
    tip.className = "tip";
    tip.style.display = "none";
    const cross = el("line", { class: "crosshair", y1: PAD.t, y2: p.h - PAD.b });
    cross.style.display = "none";
    p.svg.appendChild(cross);

    const hit = el("rect", {
      x: PAD.l, y: PAD.t, width: p.w - PAD.l - PAD.r, height: p.h - PAD.t - PAD.b, fill: "transparent",
    });
    p.svg.appendChild(hit);

    hit.addEventListener("mousemove", (e) => {
      const box = p.svg.getBoundingClientRect();
      const vx = ((e.clientX - box.left) / box.width) * p.w; // css px -> viewBox units
      const frac = (vx - PAD.l) / (p.w - PAD.l - PAD.r);
      const i = Math.round(Math.min(1, Math.max(0, frac)) * (history.length - 1));
      const b = history[i];
      cross.setAttribute("x1", p.x(i, history.length));
      cross.setAttribute("x2", p.x(i, history.length));
      cross.style.display = "";
      fillTip(tip, new Date(b.minute * 60000), rowsFor(b, i));
      tip.style.display = "";
      tip.style.left = Math.min(box.width - tip.offsetWidth, e.clientX - box.left + 10) + "px";
    });
    hit.addEventListener("mouseleave", () => {
      tip.style.display = "none";
      cross.style.display = "none";
    });
  }

  const DRAW = { queries: drawQueries, cache: drawCache, latency: drawLatency };

  window.kydnsDrawCharts = function (history) {
    if (!history || !history.length) return;
    document.querySelectorAll("[data-chart]").forEach((fig) => {
      const fn = DRAW[fig.dataset.chart];
      if (fn) fn(fig, history);
    });
  };
})();
