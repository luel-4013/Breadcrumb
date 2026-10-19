/* Breadcrumb UI behaviours: command palette, tabs, toasts, copy, sidebar. */
(function () {
  "use strict";

  // ---------- toasts ----------
  function toast(msg, kind) {
    var host = document.getElementById("toasts");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () {
      el.style.opacity = "0";
      setTimeout(function () { el.remove(); }, 200);
    }, 2600);
  }
  window.toast = toast;

  // ---------- theme toggle (Tailwind-style manual dark mode) ----------
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("bc-theme");
    root.setAttribute("data-theme", saved === "light" ? "light" : "dark");
  } catch (e) { root.setAttribute("data-theme", "dark"); }
  document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("bc-theme", next); } catch (e) {}
      toast(next === "light" ? "Light theme" : "Dark theme", "");
    });
  });

  // ---------- confirm dialog for destructive forms ----------
  var dlg = document.getElementById("confirmDlg");
  var pendingForm = null;
  if (dlg && dlg.showModal) {
    document.addEventListener("submit", function (e) {
      var form = e.target;
      if (!form.matches || !form.matches("form[data-confirm]") || form.dataset.armed) return;
      e.preventDefault();
      pendingForm = form;
      var msg = document.getElementById("confirmMsg");
      if (msg) msg.textContent = form.getAttribute("data-confirm") || "This cannot be undone.";
      dlg.showModal();
    });
    dlg.addEventListener("close", function () {
      if (dlg.returnValue === "yes" && pendingForm) {
        pendingForm.dataset.armed = "1";
        pendingForm.submit();
      }
      pendingForm = null;
    });
  }

  // ---------- landing toasts (?done=1 / ?msg=… after actions) ----------
  (function () {
    var url = new URL(window.location);
    if (url.searchParams.get("done") === "1") {
      toast("AI analysis saved.", "ok");
      url.searchParams.delete("done");
      history.replaceState(null, "", url);
    }
    var msg = url.searchParams.get("msg");
    if (msg) {
      toast(msg, msg.indexOf("[ERR") === 0 || msg.indexOf("[err") === 0 ? "err" : "ok");
      url.searchParams.delete("msg");
      history.replaceState(null, "", url);
    }
  })();

  // ---------- copy buttons ----------
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    var value = btn.getAttribute("data-copy");
    navigator.clipboard.writeText(value).then(
      function () { toast("Copied " + (value.length > 40 ? value.slice(0, 40) + "…" : value), "ok"); },
      function () { toast("Copy failed", "err"); }
    );
  });

  // ---------- print / save as PDF ----------
  document.querySelectorAll("[data-print]").forEach(function (btn) {
    btn.addEventListener("click", function () { window.print(); });
  });

  // ---------- sidebar toggle (mobile) ----------
  var sideToggle = document.getElementById("sideToggle");
  if (sideToggle) {
    sideToggle.addEventListener("click", function () {
      document.getElementById("side").classList.toggle("open");
    });
  }

  // ---------- tabs ----------
  function activateTab(root, name) {
    root.querySelectorAll(".tab").forEach(function (t) {
      t.classList.toggle("active", t.getAttribute("data-tab") === name);
    });
    root.querySelectorAll(".tabpanel").forEach(function (p) {
      p.classList.toggle("active", p.getAttribute("data-panel") === name);
    });
  }
  document.querySelectorAll("[data-tabs]").forEach(function (root) {
    root.querySelectorAll(".tab").forEach(function (t) {
      t.addEventListener("click", function () {
        var name = t.getAttribute("data-tab");
        activateTab(root, name);
        var url = new URL(window.location);
        url.searchParams.set("tab", name);
        history.replaceState(null, "", url);
      });
    });
    var wants = new URL(window.location).searchParams.get("tab");
    if (wants && root.querySelector('.tab[data-tab="' + wants + '"]')) activateTab(root, wants);
  });

  // ---------- command palette ----------
  var palette = document.getElementById("palette");
  var input = document.getElementById("paletteInput");
  var results = document.getElementById("paletteResults");
  var selected = -1;
  var items = [];

  function openPalette() {
    palette.hidden = false;
    input.value = "";
    render("");
    input.focus();
  }
  function closePalette() { palette.hidden = true; }

  function render(q) {
    fetch("/api/search?q=" + encodeURIComponent(q))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        items = data.results || [];
        results.innerHTML = "";
        if (!items.length) {
          results.innerHTML = '<div class="palette-hint">No matches.</div>';
          return;
        }
        items.forEach(function (it, i) {
          var a = document.createElement("a");
          a.className = "palette-item" + (i === 0 ? " sel" : "");
          a.href = it.href;
          a.innerHTML =
            '<span class="ptype">' + esc(it.type) + '</span>' +
            '<span class="plabel">' + esc(it.label) + '</span>' +
            (it.sub ? '<span class="psub">' + esc(it.sub) + "</span>" : "");
          results.appendChild(a);
        });
        selected = 0;
      });
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function move(dir) {
    var nodes = results.querySelectorAll(".palette-item");
    if (!nodes.length) return;
    selected = (selected + dir + nodes.length) % nodes.length;
    nodes.forEach(function (n, i) { n.classList.toggle("sel", i === selected); });
    nodes[selected].scrollIntoView({ block: "nearest" });
  }

  document.querySelectorAll("[data-palette-open]").forEach(function (el) {
    el.addEventListener("click", openPalette);
  });
  if (palette) {
    palette.querySelectorAll("[data-palette-close]").forEach(function (el) {
      el.addEventListener("click", closePalette);
    });
    input.addEventListener("input", function () { render(input.value); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") {
        var sel = results.querySelector(".palette-item.sel");
        if (sel) window.location = sel.href;
      }
    });
  }
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      palette.hidden ? openPalette() : closePalette();
    } else if (e.key === "Escape" && palette && !palette.hidden) {
      closePalette();
    }
  });

  // ---------- AI button loading state ----------
  document.querySelectorAll("form[data-ai]").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector("button[type=submit]");
      if (!btn) return;
      btn.disabled = true;
      var label = btn.getAttribute("data-label") || btn.textContent;
      btn.setAttribute("data-label", label);
      btn.textContent = "Thinking…";
      toast("Asking the local model — this can take a moment.", "");
    });
  });

  // ---------- knowledge graph (SVG) ----------
  function typeHue(t) {
    var h = 0, i;
    t = String(t || "");
    for (i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) % 360;
    return h;
  }
  function svgEl(tag, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    return e;
  }
  function renderCluster(cluster) {
    var nodes = cluster.nodes || [];
    if (!nodes.length) return null;
    var R = Math.max(74, nodes.length * 9);
    var pad = 70;
    var size = 2 * (R + pad);
    var cx = size / 2, cy = size / 2;
    var svg = svgEl("svg", { viewBox: "0 0 " + size + " " + size, role: "img" });
    var pos = {};
    nodes.forEach(function (n, i) {
      var a = (2 * Math.PI * i) / nodes.length - Math.PI / 2;
      pos[n.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a), a: a, n: n };
    });
    // edges
    (cluster.edges || []).forEach(function (ed) {
      var s = pos[ed.s], d = pos[ed.d];
      if (!s || !d) return;
      var mx = (s.x + d.x) / 2, my = (s.y + d.y) / 2;
      var qx = (mx + cx) / 2, qy = (my + cy) / 2;
      var path = svgEl("path", { class: "edge", d: "M" + s.x + " " + s.y + " Q" + qx + " " + qy + " " + d.x + " " + d.y });
      svg.appendChild(path);
    });
    // spokes to center for nodes without edges (keeps star readable)
    var degree = {};
    (cluster.edges || []).forEach(function (ed) { degree[ed.s] = 1; degree[ed.d] = 1; });
    nodes.forEach(function (n) {
      var p = pos[n.id];
      if (!degree[n.id]) {
        svg.appendChild(svgEl("line", { class: "edge", x1: cx, y1: cy, x2: p.x, y2: p.y }));
      }
    });
    // center target node
    svg.appendChild(svgEl("circle", { cx: cx, cy: cy, r: 17, fill: "#6e8bff", opacity: "0.16", stroke: "#6e8bff", "stroke-width": "1.4" }));
    var t = svgEl("text", { x: cx, y: cy + 4, "text-anchor": "middle", class: "node-label node-root" });
    t.textContent = (cluster.target || "target").slice(0, 22);
    svg.appendChild(t);
    // nodes
    nodes.forEach(function (n) {
      var p = pos[n.id];
      var hue = typeHue(n.type);
      svg.appendChild(svgEl("circle", { cx: p.x, cy: p.y, r: 5, fill: "hsl(" + hue + ",62%,60%)", stroke: "#0b0c0f", "stroke-width": "1.5" }));
      var left = Math.cos(p.a) < -0.2;
      var tx = p.x + (left ? -9 : 9);
      var lbl = svgEl("text", { x: tx, y: p.y + 3, class: "node-label", "text-anchor": left ? "end" : "start" });
      var text = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
      lbl.textContent = text;
      var title = svgEl("title", {});
      title.textContent = n.type + ": " + n.label;
      lbl.appendChild(title);
      svg.appendChild(lbl);
    });
    return svg;
  }
  var canvas = document.getElementById("graphCanvas");
  if (canvas && window.__CLUSTERS) {
    window.__CLUSTERS.forEach(function (c) {
      var svg = renderCluster(c);
      if (!svg) return;
      var card = document.createElement("section");
      card.className = "card";
      var h = document.createElement("h3");
      h.textContent = c.target + (c.kind ? "  (" + c.kind + ")" : "") +
        (c.omitted ? "  · +" + c.omitted + " more not shown" : "");
      var wrap = document.createElement("div");
      wrap.className = "graph-wrap";
      wrap.appendChild(svg);
      card.appendChild(h);
      card.appendChild(wrap);
      canvas.appendChild(card);
    });
    if (!canvas.children.length) {
      canvas.innerHTML = '<p class="empty">Nothing to plot yet.</p>';
    }
  }
})();

