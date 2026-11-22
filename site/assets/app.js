/* Live dashboard for the lab page.
 * Security notes:
 *  - Loaded as an external file, so it works under a CSP without 'unsafe-inline'.
 *  - Log-derived strings (usernames, paths) are attacker-controlled. They are
 *    only ever inserted with textContent / createTextNode, never innerHTML.
 */
(function () {
  "use strict";

  var SVG_NS = "http://www.w3.org/2000/svg";
  var RELOAD_MS = 10 * 60 * 1000;   // data is regenerated every 20 min on the server
  var nf = new Intl.NumberFormat("en-US");
  var data = null;
  var series = "ssh_attempts";

  var SERIES = {
    ssh_attempts: { title: "Failed SSH login attempts per hour", unit: "failed SSH attempts" },
    web_attacks: { title: "Malicious web requests per hour", unit: "malicious web requests" }
  };

  var CATEGORY_NAMES = {
    secrets: "Hunting secrets (.env, .git, .aws …)",
    admin_panels: "Admin panels, PHP, known CVE paths",
    wordpress: "WordPress probes",
    traversal_rce: "Path traversal / command injection",
    unknown_host: "Bare IP / unknown name (dropped)",
    method_probe: "Unusual HTTP methods (TRACE …)",
    not_found: "Other non-existent pages",
    malformed: "Malformed or non-HTTP requests"
  };

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }

  function svg(tag, attrs) {
    var e = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    return e;
  }

  function get(obj, path) {
    return path.split(".").reduce(function (o, k) { return o == null ? o : o[k]; }, obj);
  }

  function fmt(n) { return typeof n === "number" ? nf.format(n) : "-"; }

  function relTime(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return "unknown";
    var min = Math.round((Date.now() - t) / 60000);
    if (min < 1) return "just now";
    if (min < 60) return min + " min ago";
    var h = Math.round(min / 60);
    if (h < 48) return h + (h === 1 ? " hour ago" : " hours ago");
    return Math.round(h / 24) + " days ago";
  }

  function fillList(id, rows, labelFn) {
    var ol = $(id);
    if (!ol) return;
    ol.textContent = "";
    if (!rows || !rows.length) {
      ol.appendChild(el("li", "none", "Nothing in the last 24 hours"));
      return;
    }
    rows.forEach(function (r) {
      var li = el("li");
      li.appendChild(el("span", "name", labelFn ? labelFn(r[0]) : r[0]));
      li.appendChild(el("span", "count", fmt(r[1])));
      ol.appendChild(li);
    });
  }

  function niceMax(v) {
    if (v <= 5) return 5;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var steps = [1, 2, 2.5, 5, 10];
    for (var i = 0; i < steps.length; i++) {
      if (steps[i] * p >= v) return steps[i] * p;
    }
    return 10 * p;
  }

  /* points: [{label, value, tip, partial, tick}] */
  function barChart(containerId, points, width) {
    var box = $(containerId);
    if (!box) return;
    box.textContent = "";
    var W = width || 720, H = 200, L = 40, R = 8, T = 10, B = 26;
    var s = svg("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "xMidYMid meet" });
    var max = 0;
    points.forEach(function (p) { if (p.value > max) max = p.value; });
    if (!points.length || max === 0) {
      var t = svg("text", { x: W / 2, y: H / 2, "text-anchor": "middle", "class": "empty" });
      t.textContent = "No data yet";
      s.appendChild(t);
      box.appendChild(s);
      return;
    }
    var top = niceMax(max);
    var plotW = W - L - R, plotH = H - T - B;
    [0, 0.5, 1].forEach(function (f) {
      var y = T + plotH - f * plotH;
      s.appendChild(svg("line", { x1: L, x2: W - R, y1: y, y2: y, "class": f === 0 ? "axis" : "grid" }));
      var lab = svg("text", { x: L - 6, y: y + 4, "text-anchor": "end" });
      lab.textContent = nf.format(Math.round(top * f));
      s.appendChild(lab);
    });
    var slot = plotW / points.length;
    var bw = Math.max(2, Math.min(28, slot - 3));
    points.forEach(function (p, i) {
      var h = p.value / top * plotH;
      var x = L + i * slot + (slot - bw) / 2;
      var r = svg("rect", {
        x: x.toFixed(1), y: (T + plotH - h).toFixed(1),
        width: bw.toFixed(1), height: Math.max(h, p.value > 0 ? 1 : 0).toFixed(1),
        rx: Math.min(3, bw / 2), "class": "bar" + (p.partial ? " partial" : "")
      });
      var title = svg("title");
      title.textContent = p.tip;
      r.appendChild(title);
      s.appendChild(r);
      if (p.tick) {
        var tl = svg("text", { x: (L + i * slot + slot / 2).toFixed(1), y: H - 8, "text-anchor": "middle" });
        tl.textContent = p.label;
        s.appendChild(tl);
      }
    });
    box.appendChild(s);
  }

  function table(containerId, head, rows) {
    var box = $(containerId);
    if (!box) return;
    box.textContent = "";
    var t = el("table", "datatable");
    var tr = el("tr");
    head.forEach(function (h) { tr.appendChild(el("th", null, h)); });
    var thead = el("thead"); thead.appendChild(tr); t.appendChild(thead);
    var tb = el("tbody");
    rows.forEach(function (r) {
      var row = el("tr");
      r.forEach(function (c) { row.appendChild(el("td", null, c)); });
      tb.appendChild(row);
    });
    t.appendChild(tb);
    box.appendChild(t);
  }

  function hourLabel(i) {
    var t = new Date(Date.parse(data.hourly.start_utc) + i * 3600000);
    return String(t.getHours()).padStart(2, "0") + ":00";
  }

  function renderHourly() {
    var h = data.hourly, vals = h[series] || [], last = vals.length - 1;
    $("hourly-title").textContent = SERIES[series].title;
    barChart("chart-hourly", vals.map(function (v, i) {
      return { label: hourLabel(i), value: v, tick: i % 3 === 0, partial: i === last,
        tip: hourLabel(i) + " · " + fmt(v) + " " + SERIES[series].unit + (i === last ? " (hour in progress)" : "") };
    }));
    table("table-hourly", ["Hour (your time)", "Failed SSH", "Malicious web"],
      vals.map(function (_v, i) {
        return [hourLabel(i), fmt(h.ssh_attempts[i]), fmt(h.web_attacks[i])];
      }));
    document.querySelectorAll(".toggle button").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-series") === series ? "true" : "false");
    });
  }

  function render() {
    var d = data;
    document.querySelectorAll("[data-k]").forEach(function (node) {
      node.textContent = fmt(get(d, node.getAttribute("data-k")));
    });

    var up = $("updated");
    var ageMin = (Date.now() - Date.parse(d.generated_utc)) / 60000;
    var stale = !(ageMin < 60);   // the server writes every 20 min: 60+ means it is behind
    up.textContent = "Updated " + relTime(d.generated_utc) + (stale ? " (update delayed)" : "");
    up.className = stale ? "pill" : "pill ok";
    up.title = d.generated_utc;

    renderHourly();

    var daily = (d.daily || []).map(function (day, i, arr) {
      var partial = day.hours < 24, total = day.ssh + day.web;
      return { label: day.date.slice(5), value: total, partial: partial,
        tick: arr.length <= 10 || i % Math.ceil(arr.length / 8) === 0,
        tip: day.date + " · " + fmt(day.ssh) + " SSH + " + fmt(day.web) + " web attempts" +
          (partial ? " (partial day)" : "") };
    });
    barChart("chart-daily", daily);
    table("table-daily", ["Date", "Failed SSH", "Malicious web", "Blocked (Fail2ban)"],
      (d.daily || []).map(function (day) {
        return [day.date + (day.hours < 24 ? " *" : ""), fmt(day.ssh), fmt(day.web), fmt(day.bans)];
      }));

    var t = d.tried || {};
    fillList("top-users", t.ssh_usernames);
    fillList("top-paths", t.web_paths);
    fillList("top-types", t.web_attack_types, function (k) { return CATEGORY_NAMES[k] || k; });
  }

  function fail() {
    if (data) return;               // keep the last good data on a failed refresh
    $("live-error").hidden = false;
    var up = $("updated");
    up.textContent = "Offline";
    up.className = "pill";
  }

  function load() {
    fetch("data/stats.json", { cache: "no-store", credentials: "omit" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        if (!d || d.schema !== 3) throw new Error("schema");
        data = d;
        $("live-error").hidden = true;
        render();
      })
      .catch(fail);
  }

  function wireToggle() {
    document.querySelectorAll(".toggle button").forEach(function (b) {
      b.addEventListener("click", function () {
        series = b.getAttribute("data-series");
        if (data) renderHourly();
      });
    });
  }

  // Hide screenshots that are not uploaded yet (no inline onerror: CSP).
  function wireGallery() {
    var shots = document.querySelectorAll(".shot img");
    var missing = 0;
    function gone(img) {
      var fig = img.closest("figure");
      if (fig && !fig.hidden) { fig.hidden = true; missing++; }
      if (missing === shots.length) $("no-shots").hidden = false;
    }
    shots.forEach(function (img) {
      if (img.complete && img.naturalWidth === 0) gone(img);
      img.addEventListener("error", function () { gone(img); });
    });
  }

  // Click a screenshot to see it large. Close with the X button, Esc, or a click outside the picture.
  function wireLightbox() {
    var box = document.createElement("div");
    box.className = "lightbox";
    box.hidden = true;
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-label", "Screenshot");
    var close = document.createElement("button");
    close.type = "button";
    close.className = "lightbox-close";
    close.setAttribute("aria-label", "Close");
    close.textContent = "\u00d7";
    var big = document.createElement("img");
    var cap = document.createElement("p");
    cap.className = "lightbox-cap";
    box.appendChild(close);
    box.appendChild(big);
    box.appendChild(cap);
    document.body.appendChild(box);
    var opener = null;

    function hide() {
      box.hidden = true;
      big.removeAttribute("src");
      document.body.classList.remove("no-scroll");
      if (opener) opener.focus();
    }
    function show(a) {
      opener = a;
      var thumb = a.querySelector("img");
      var fc = a.closest("figure").querySelector("figcaption");
      big.src = a.getAttribute("href");
      big.alt = thumb ? thumb.alt : "";
      cap.textContent = fc ? fc.textContent : "";
      box.hidden = false;
      document.body.classList.add("no-scroll");
      close.focus();
    }
    document.querySelectorAll(".shot a").forEach(function (a) {
      a.addEventListener("click", function (e) { e.preventDefault(); show(a); });
    });
    close.addEventListener("click", hide);
    box.addEventListener("click", function (e) { if (e.target !== big) hide(); });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !box.hidden) hide(); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireGallery();
    wireLightbox();
    wireToggle();
    load();
    setInterval(function () { if (!document.hidden) load(); }, RELOAD_MS);
    document.addEventListener("visibilitychange", function () { if (!document.hidden && data) load(); });
  });
})();
