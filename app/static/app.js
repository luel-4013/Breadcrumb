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

  // ---------- settings: model picker / tester ----------
  var picker = document.getElementById("modelPicker");
  if (picker) {
    var providerSelect = document.getElementById("modelProvider");
    var refreshBtn = document.getElementById("modelRefresh");
    var statusEl = document.getElementById("modelStatus");
    var summaryEl = document.getElementById("modelSummary");
    var listEl = document.getElementById("modelList");
    var suggestionsEl = document.getElementById("modelSuggestions");
    var suggestionListEl = document.getElementById("modelSuggestionList");
    var csrfMeta = document.querySelector('meta[name="csrf-token"]');
    var csrfToken = csrfMeta ? csrfMeta.getAttribute("content") : "";
    var pickerState = null;

    function pickerNode(tag, cls, text) {
      var node = document.createElement(tag);
      if (cls) node.className = cls;
      if (text != null) node.textContent = String(text);
      return node;
    }

    function pickerBadge(text, cls) {
      return pickerNode("span", "chip " + (cls || ""), text);
    }

    function setPickerStatus(kind, text, showRetry) {
      statusEl.className = "picker-status " + (kind || "");
      statusEl.innerHTML = "";
      statusEl.appendChild(pickerNode("span", "status-dot"));
      statusEl.appendChild(pickerNode("span", "status-text", text));
      if (showRetry) {
        var retry = pickerNode("button", "btn sm ghost", "Retry");
        retry.type = "button";
        retry.addEventListener("click", loadModels);
        statusEl.appendChild(retry);
      }
    }

    function providerHint(providerId) {
      if (providerId && providerId.indexOf("jan") !== -1) {
        return "Open Jan → Settings → Local API Server and start it on port 1337.";
      }
      return "Start LM Studio → Developer → Start Server on port 1234.";
    }

    function loadModels() {
      var provider = providerSelect ? providerSelect.value : "";
      if (!provider) {
        setPickerStatus("bad", "No provider configured. Add one above, then refresh.");
        return;
      }
      var label = providerSelect.options[providerSelect.selectedIndex].textContent;
      setPickerStatus("checking", "Checking " + label + "…");
      summaryEl.textContent = "";
      listEl.innerHTML = "";
      suggestionsEl.hidden = true;
      refreshBtn.disabled = true;

      fetch("/api/llm/models?detailed=1&provider=" + encodeURIComponent(provider))
        .then(function (response) { return response.json(); })
        .then(function (state) {
          pickerState = state;
          renderPicker(state);
        })
        .catch(function (err) {
          pickerState = null;
          setPickerStatus("bad", "Could not reach Breadcrumb: " + err.message, true);
          summaryEl.textContent = "";
          listEl.innerHTML = "";
          suggestionsEl.hidden = true;
        })
        .then(function () { refreshBtn.disabled = false; });
    }

    function renderPicker(state) {
      if (!state || !state.ok) {
        var error = (state && state.error) ? state.error : "provider is not reachable";
        setPickerStatus("bad", "Provider offline — " + error, true);
        summaryEl.textContent = providerHint(state && state.provider);
        renderSuggestions((state && state.suggestions) || [], []);
        return;
      }

      var models = state.models || [];
      var loaded = models.filter(function (m) { return String(m.state).toLowerCase() === "loaded"; }).length;
      var fits = models.filter(function (m) { return m.fit && m.fit.level === "fits"; }).length;
      var tight = models.filter(function (m) { return m.fit && m.fit.level === "tight"; }).length;
      var tooLarge = models.filter(function (m) { return m.fit && m.fit.level === "too-large"; }).length;

      setPickerStatus("ok", (state.provider_label || state.provider) + " · online");
      summaryEl.innerHTML = "";
      if (state.gpu && state.gpu.name) {
        summaryEl.appendChild(pickerNode(
          "span", "summary-piece",
          state.gpu.name + " · " + state.gpu.free_gb + " GB free of " + state.gpu.total_gb + " GB"
        ));
      }
      summaryEl.appendChild(pickerNode(
        "span", "summary-piece",
        models.length + " model" + (models.length === 1 ? "" : "s") + " · " +
        fits + " fit" + (fits === 1 ? "" : "") + " 4 GB" +
        (tight ? " · " + tight + " tight" : "") +
        (tooLarge ? " · " + tooLarge + " too large" : "") +
        (loaded ? " · " + loaded + " loaded" : "")
      ));
      (state.notes || []).forEach(function (note) {
        summaryEl.appendChild(pickerNode("div", "summary-note", note));
      });
      if (state.autofit_hint) {
        summaryEl.appendChild(pickerNode("div", "summary-note warn-text", state.autofit_hint));
      }

      listEl.innerHTML = "";
      if (!models.length) {
        listEl.appendChild(pickerNode(
          "div", "empty-state",
          "No models reported. Download one in LM Studio, then Refresh."
        ));
      } else {
        models.forEach(function (model) { listEl.appendChild(renderModel(model, state)); });
      }
      renderSuggestions(state.suggestions || [], models);
    }

    function renderModel(model, state) {
      var fitLevel = (model.fit && model.fit.level) || "unknown";
      var card = pickerNode("article", "model-card fit-" + fitLevel);

      var head = pickerNode("div", "model-head");
      var title = pickerNode("div", "model-title");
      title.appendChild(pickerNode("div", "model-name mono", model.id));
      var subParts = [model.display_name, model.publisher, model.params, model.quantization]
        .filter(function (part) { return part && part !== model.id; });
      if (subParts.length) {
        title.appendChild(pickerNode("div", "model-sub", subParts.join(" · ")));
      }
      head.appendChild(title);

      var badges = pickerNode("div", "model-badges");
      badges.appendChild(pickerBadge(
        (model.fit && model.fit.label) || "Fit unknown",
        "fit-badge fit-" + fitLevel
      ));
      if (String(model.state).toLowerCase() === "loaded") {
        badges.appendChild(pickerBadge("loaded", "state-loaded"));
      } else if (model.state && model.state !== "unknown") {
        badges.appendChild(pickerBadge(model.state, ""));
      }
      head.appendChild(badges);
      card.appendChild(head);

      var roles = pickerNode("div", "model-roles");
      (model.role_labels || []).forEach(function (role) {
        roles.appendChild(pickerNode("span", "chip role-chip", role));
      });
      card.appendChild(roles);

      card.appendChild(pickerNode("p", "model-note", model.note || ""));
      if (model.fit && model.fit.note) {
        card.appendChild(pickerNode("p", "model-note fit-note", model.fit.note));
      }

      var meta = [];
      if (model.size_label) meta.push("size " + model.size_label);
      if (model.max_context_label && model.max_context_label !== "?") {
        meta.push("model max " + model.max_context_label);
      }
      if (model.loaded_context) meta.push("loaded at " + model.loaded_context);
      if (model.fit && model.fit.vram_gb) meta.push("GPU " + model.fit.vram_gb + " GB");
      card.appendChild(pickerNode("div", "model-meta", meta.join(" · ")));

      var actions = pickerNode("div", "model-actions");
      var isEmbedding = (model.roles || []).indexOf("embedding") !== -1;
      var testBtn = pickerNode("button", "btn sm", "Test");
      testBtn.type = "button";
      testBtn.title = "Send a tiny prompt and measure speed/output.";
      if (isEmbedding) {
        testBtn.disabled = true;
        testBtn.title = "Embedding models are not chat models.";
      }
      testBtn.addEventListener("click", function () { runModelTest(model, false, card, state); });
      actions.appendChild(testBtn);

      var autofitBtn = null;
      if (state.can_autofit && !isEmbedding) {
        autofitBtn = pickerNode("button", "btn sm ghost", "Auto-fit + test");
        autofitBtn.type = "button";
        autofitBtn.title = "Probe descending context sizes and keep the largest that works.";
        autofitBtn.addEventListener("click", function () {
          var ok = window.confirm(
            "Auto-fit will unload and reload “" + model.id + "” in LM Studio, trying " +
            "several context sizes, largest first. This can take a minute. Continue?"
          );
          if (ok) runModelTest(model, true, card, state);
        });
        actions.appendChild(autofitBtn);
      }

      var routeSelect = pickerNode("select", "route-select");
      routeSelect.setAttribute("aria-label", "Use model for route");
      [["", "Use for…"], ["all", "All routes"], ["fast", "Fast / bulk"],
       ["reason", "Reasoning"], ["long", "Long context"], ["prose", "Prose / reports"]
      ].forEach(function (pair) {
        var option = document.createElement("option");
        option.value = pair[0];
        option.textContent = pair[1];
        routeSelect.appendChild(option);
      });
      routeSelect.disabled = isEmbedding;
      actions.appendChild(routeSelect);

      var useBtn = pickerNode("button", "btn sm", "Use");
      useBtn.type = "button";
      useBtn.disabled = isEmbedding;
      useBtn.addEventListener("click", function () {
        applyModelRoute(model, routeSelect, card, useBtn);
      });
      actions.appendChild(useBtn);
      card.appendChild(actions);

      if (isEmbedding) {
        card.appendChild(pickerNode("p", "model-warning", "Embedding model — not selectable for chat routes."));
      } else if (fitLevel === "too-large") {
        card.appendChild(pickerNode(
          "p", "model-warning",
          "Warning: this model is larger than VRAM. It stays selectable, but expect slow partial offload."
        ));
      }

      var result = pickerNode("div", "model-result");
      result.hidden = true;
      result.setAttribute("aria-live", "polite");
      card.appendChild(result);
      return card;
    }

    function setCardBusy(card, busy) {
      card.querySelectorAll("button, select").forEach(function (node) {
        if (busy) {
          node.setAttribute("data-was-disabled", node.disabled ? "1" : "0");
          node.disabled = true;
        } else if (node.getAttribute("data-was-disabled") === "0") {
          node.disabled = false;
        }
      });
    }

    function runModelTest(model, autoFit, card, state) {
      var resultEl = card.querySelector(".model-result");
      setCardBusy(card, true);
      resultEl.hidden = false;
      resultEl.className = "model-result testing";
      resultEl.textContent = autoFit
        ? "Auto-fitting context… trying the largest size first. This can take a minute."
        : "Testing model…";

      fetch("/api/llm/test", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({
          provider: state.provider,
          model: model.id,
          auto_fit: autoFit
        })
      })
        .then(function (response) {
          return response.json().then(function (data) {
            return { status: response.status, data: data };
          });
        })
        .then(function (out) {
          renderTestResult(resultEl, out.data, out.status);
        })
        .catch(function (err) {
          resultEl.className = "model-result fail";
          resultEl.textContent = "Test failed: " + err.message;
        })
        .then(function () { setCardBusy(card, false); });
    }

    function renderTestResult(resultEl, data, status) {
      resultEl.innerHTML = "";
      resultEl.hidden = false;
      if (!data) {
        resultEl.className = "model-result fail";
        resultEl.textContent = "Test failed: empty response (HTTP " + status + ").";
        return;
      }
      var kind = "ok";
      var headline = "OK";
      if (status === 403) {
        kind = "fail";
        headline = "Test blocked — reload the page for a fresh CSRF token";
      } else if (!data.ok) {
        kind = "fail";
        headline = "Test failed";
      } else if (data.verdict === "reasoning-only") {
        kind = "warn";
        headline = "Responded — reasoning only";
      } else if (data.verdict === "empty") {
        kind = "warn";
        headline = "Responded — empty content";
      } else if (data.verdict === "truncated") {
        kind = "warn";
        headline = "Responded — output hit the token limit";
      } else if (data.tok_per_s) {
        headline = "OK — " + data.tok_per_s.toFixed(1) + " tok/s";
      }
      resultEl.className = "model-result " + kind;
      var head = pickerNode("div", "test-head");
      head.appendChild(pickerNode("strong", "", headline));
      if (data.verdict && data.ok) {
        head.appendChild(pickerNode("span", "test-verdict", data.verdict));
      }
      resultEl.appendChild(head);

      var metrics = [];
      if (data.elapsed_s != null) metrics.push(data.elapsed_s + " s");
      if (data.completion_tokens) metrics.push(data.completion_tokens + " tokens");
      if (data.tok_per_s) metrics.push(data.tok_per_s + " tok/s");
      if (data.context_label) metrics.push("context " + data.context_label);
      if (data.load_s != null) metrics.push("load " + data.load_s + " s");
      if (metrics.length) resultEl.appendChild(pickerNode("div", "test-metrics", metrics.join(" · ")));

      if (data.error) {
        resultEl.appendChild(pickerNode("div", "test-warning", data.error));
      }

      if (data.auto_fit && data.auto_fit.attempts && data.auto_fit.attempts.length) {
        var details = document.createElement("details");
        var summary = document.createElement("summary");
        summary.textContent = "Context probes (" + data.auto_fit.attempts.length + ")";
        details.appendChild(summary);
        data.auto_fit.attempts.forEach(function (attempt) {
          var line = attempt.context_label + ": " + (attempt.ok ? "loaded" : "failed");
          if (attempt.load_s != null) line += " (" + attempt.load_s + " s)";
          if (attempt.error) line += " — " + attempt.error;
          details.appendChild(pickerNode("div", "probe-line " + (attempt.ok ? "ok" : "bad"), line));
        });
        resultEl.appendChild(details);
      }

      if (data.content) {
        resultEl.appendChild(pickerNode("div", "test-reply-label", "Reply"));
        resultEl.appendChild(pickerNode("pre", "test-reply", data.content.slice(0, 900)));
      } else if (data.reasoning) {
        resultEl.appendChild(pickerNode("div", "test-reply-label", "Reasoning (content was empty)"));
        resultEl.appendChild(pickerNode("pre", "test-reply", data.reasoning.slice(0, 900)));
      }
    }

    function applyModelRoute(model, routeSelect, card, useBtn) {
      var task = routeSelect.value;
      if (!task) {
        toast("Choose a route first.", "err");
        return;
      }
      useBtn.disabled = true;
      fetch("/api/llm/routes", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
        body: JSON.stringify({ task: task, model: model.id })
      })
        .then(function (response) {
          return response.json().then(function (data) {
            return { status: response.status, data: data };
          });
        })
        .then(function (out) {
          if (out.status !== 200 || !out.data.ok) {
            throw new Error(out.data.detail || ("HTTP " + out.status));
          }
          Object.keys(out.data.routing || {}).forEach(function (name) {
            var input = document.getElementById("route_" + name);
            if (input) input.value = out.data.routing[name];
          });
          var message = task === "all"
            ? "All routes now use " + model.id
            : "Route updated: " + task + " → " + model.id;
          toast(message, "ok");
          card.classList.add("route-selected");
        })
        .catch(function (err) {
          toast("Could not update routing: " + err.message, "err");
        })
        .then(function () { useBtn.disabled = false; });
    }

    function renderSuggestions(suggestions, models) {
      suggestionListEl.innerHTML = "";
      if (!suggestions.length) {
        suggestionsEl.hidden = true;
        return;
      }
      var installed = {};
      (models || []).forEach(function (model) { installed[String(model.id).toLowerCase()] = true; });
      suggestions.forEach(function (suggestion) {
        var row = pickerNode("div", "suggestion");
        var head = pickerNode("div", "suggestion-head");
        head.appendChild(pickerNode("span", "suggestion-name", suggestion.name));
        head.appendChild(pickerNode("span", "chip", suggestion.size));
        if (suggestion.installed || installed[String(suggestion.id).toLowerCase()]) {
          head.appendChild(pickerBadge("installed", "state-loaded"));
        }
        row.appendChild(head);
        var roles = pickerNode("div", "model-roles");
        (suggestion.role_labels || []).forEach(function (role) {
          roles.appendChild(pickerNode("span", "chip role-chip", role));
        });
        row.appendChild(roles);
        row.appendChild(pickerNode("p", "model-note", suggestion.why || ""));
        var link = document.createElement("a");
        link.href = suggestion.url;
        link.target = "_blank";
        link.rel = "noreferrer noopener";
        link.className = "suggestion-link";
        link.textContent = "Open download page ↗";
        row.appendChild(link);
        suggestionListEl.appendChild(row);
      });
      suggestionsEl.hidden = false;
    }

    if (providerSelect) providerSelect.addEventListener("change", loadModels);
    if (refreshBtn) refreshBtn.addEventListener("click", loadModels);
    loadModels();
  }
})();

