document.documentElement.classList.add("js");

(function () {
  var bar = document.querySelector("header[data-nav]");
  if (!bar) return;
  var btn = bar.querySelector("[data-nav-button]");
  function set(open, back) {
    if (open) bar.removeAttribute("data-collapsed"); else bar.setAttribute("data-collapsed", "");
    if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
    if (!open && back && btn) btn.focus();
  }
  function isOpen() { return btn && btn.getAttribute("aria-expanded") === "true"; }
  set(false);
  if (btn) btn.addEventListener("click", function () { set(!isOpen(), false); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && isOpen() && !document.querySelector("dialog[open]")) { e.preventDefault(); set(false, true); }
  });
  document.addEventListener("click", function (e) {
    if (!isOpen()) return;
    var panel = bar.querySelector(".nav-panel");
    if (!bar.contains(e.target) || (panel && panel.contains(e.target) && e.target.closest("a"))) set(false, false);
  });
  function size() { document.documentElement.style.setProperty("--header-h", Math.ceil(bar.getBoundingClientRect().height) + "px"); }
  size();
  if (window.ResizeObserver) new ResizeObserver(size).observe(bar);
})();

// toast(message, {kind: "success"|"error"|"info", duration})
// Also accepts the legacy second argument "ok"|"bad"|"warn".
// Defaults: success 1s, error 4s, info 4s. The "Saved" confirmation is exactly 1s.
function toast(message, opts) {
  if (typeof opts === "string") opts = { kind: opts };
  opts = opts || {};
  var kind = opts.kind || "info";
  if (kind === "ok") kind = "success";
  if (kind === "bad") kind = "error";
  if (kind === "warn") kind = "info";
  var duration = opts.duration;
  if (duration == null) {
    duration = (kind === "error") ? 4000 : (kind === "success") ? 1000 : 4000;
  }
  var host = document.querySelector(".toasts");
  if (!host) {
    host = document.createElement("div");
    host.className = "toasts";
    host.setAttribute("role", "status");
    host.setAttribute("aria-live", "polite");
    host.setAttribute("aria-relevant", "additions");
    host.setAttribute("aria-atomic", "false");
    document.body.appendChild(host);
  }
  var el = document.createElement("div");
  el.className = "toast " + kind;
  el.textContent = message;
  host.appendChild(el);
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var fade = reduce ? 0 : 300;
  function dismiss() {
    el.classList.add("gone");
    setTimeout(function () { el.remove(); }, fade);
  }
  el.addEventListener("click", dismiss);
  setTimeout(dismiss, duration);
}

document.querySelectorAll(".toasts .toast").forEach(function (el) {
  var kind = "info";
  if (el.classList.contains("ok") || el.classList.contains("success")) kind = "success";
  else if (el.classList.contains("bad") || el.classList.contains("error")) kind = "error";
  var duration = kind === "success" ? 1000 : 4000;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var fade = reduce ? 0 : 300;
  function dismiss() {
    el.classList.add("gone");
    setTimeout(function () { if (el.parentNode) el.remove(); }, fade);
  }
  el.addEventListener("click", dismiss);
  setTimeout(dismiss, duration);
});

document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy-text]");
  if (!b) return;
  var text = b.getAttribute("data-copy-text");
  var done = function () { toast("Copied", {kind:"success"}); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); });
  else { fallback(text); done(); }
});
function fallback(text) {
  var t = document.createElement("textarea");
  t.value = text;
  document.body.appendChild(t);
  t.select();
  try { document.execCommand("copy"); } catch (err) {}
  t.remove();
}

document.addEventListener("submit", function (e) {
  var f = e.target;
  var msg = f.getAttribute("data-confirm");
  if (!msg || f.getAttribute("data-confirmed")) return;
  e.preventDefault();
  var d = document.getElementById("confirm");
  if (!d || !d.showModal) { f.setAttribute("data-confirmed", "1"); f.submit(); return; }
  d.querySelector("[data-confirm-text]").textContent = msg;
  var ok = d.querySelector("[data-confirm-ok]");
  var cancel = d.querySelector("[data-confirm-cancel]");
  ok.classList.toggle("confirm-danger", f.getAttribute("data-confirm-danger") === "1");
  function close() { d.close(); }
  cancel.onclick = close;
  ok.onclick = function () { close(); f.setAttribute("data-confirmed", "1"); f.submit(); };
  d.showModal();
  ok.focus();
});

(function () {
  var box = document.querySelector("[data-grok]");
  if (!box) return;
  var btn = box.querySelector("[data-grok-apply]");
  var input = box.querySelector("[data-grok-paste]");
  btn.addEventListener("click", function () {
    var parts = input.value.trim().split(/\s+/);
    if (parts.length < 2) { toast("Paste the URL and the key, separated by a space", {kind:"info"}); return; }
    var form = box.closest("form");
    form.querySelector("[name=url]").value = parts[0];
    form.querySelector("[name=secret]").value = parts.slice(1).join(" ");
    var mode = form.querySelector("[name=auth_mode]");
    if (mode) mode.value = "bearer";
    toast("URL and key filled in.", {kind:"success"});
    if (form.hasAttribute("data-autosave") && window.ghookAutosave) window.ghookAutosave(form);
  });
})();

(function () {
  var table = document.querySelector("[data-reorder]");
  if (!table) return;
  var drag = null;
  var start = "";
  function ids() {
    return [].map.call(table.querySelectorAll("tbody tr[data-id]"), function (tr) { return tr.getAttribute("data-id"); });
  }
  function save() {
    var fd = new FormData();
    fd.set("csrf", document.body.getAttribute("data-csrf") || "");
    ids().forEach(function (id) { fd.append("id", id); });
    fetch(table.getAttribute("data-reorder"), { method: "POST", body: fd, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("save"); toast("Saved", {kind:"success", duration:1000}); })
      .catch(function () { toast("Could not save the order", {kind:"error"}); });
  }
  // Only the handle starts a drag, so text in the row (and the inline editors) stays selectable.
  table.addEventListener("pointerdown", function (e) {
    var h = e.target.closest("[data-handle]");
    var tr = h && h.closest("tr[data-id]");
    if (tr) tr.setAttribute("draggable", "true");
  });
  document.addEventListener("pointerup", function () {
    table.querySelectorAll("tr[draggable]").forEach(function (tr) { if (tr !== drag) tr.removeAttribute("draggable"); });
  });
  table.addEventListener("dragstart", function (e) {
    var tr = e.target.closest && e.target.closest("tr[data-id]");
    if (!tr || !tr.hasAttribute("draggable")) { e.preventDefault(); return; }
    drag = tr;
    start = ids().join();
    tr.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", tr.getAttribute("data-id"));
  });
  // Save when the drag ends and the order changed, wherever the row was let go.
  table.addEventListener("dragend", function () {
    if (!drag) return;
    drag.classList.remove("dragging");
    drag.removeAttribute("draggable");
    drag = null;
    if (ids().join() !== start) save();
  });
  table.addEventListener("dragover", function (e) {
    if (!drag) return;
    e.preventDefault();
    var tr = e.target.closest("tr[data-id]");
    if (!tr || tr === drag) return;
    var after = e.clientY > tr.getBoundingClientRect().top + tr.getBoundingClientRect().height / 2;
    tr.parentNode.insertBefore(drag, after ? tr.nextSibling : tr);
  });
  table.addEventListener("drop", function (e) { if (drag) e.preventDefault(); });
  document.addEventListener("keydown", function (e) {
    if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
    if (e.target && e.target.matches && e.target.matches("input, textarea, select")) return;
    var tr = document.activeElement && document.activeElement.closest ? document.activeElement.closest("tr[data-id]") : null;
    if (!tr || !table.contains(tr)) return;
    e.preventDefault();
    var sib = e.key === "ArrowUp" ? tr.previousElementSibling : tr.nextElementSibling;
    if (!sib || !sib.getAttribute || !sib.getAttribute("data-id")) return;
    var keep = document.activeElement;
    if (e.key === "ArrowUp") tr.parentNode.insertBefore(tr, sib);
    else tr.parentNode.insertBefore(sib, tr);
    if (keep && keep.focus) keep.focus();
    save();
  });
})();

document.querySelectorAll("[data-filter]").forEach(function (input) {
  input.addEventListener("input", function () {
    var q = input.value.toLowerCase();
    var table = document.querySelector(input.getAttribute("data-filter"));
    if (!table) return;
    table.querySelectorAll("tbody tr").forEach(function (tr) {
      tr.hidden = q !== "" && tr.textContent.toLowerCase().indexOf(q) < 0;
    });
  });
});

(function () {
  var feed = document.querySelector("[data-feed]");
  if (!feed || !window.EventSource) return;
  var es = new EventSource(feed.getAttribute("data-feed"));
  es.onmessage = function (ev) {
    var row = document.createElement("div");
    row.className = "logline";
    var t = document.createElement("span");
    t.className = "logtime";
    var msg = document.createElement("span");
    msg.className = "logtext";
    try {
      var j = JSON.parse(ev.data);
      t.textContent = j.time || "";
      msg.textContent = j.text || "";
    } catch (err) { msg.textContent = ev.data; }
    row.appendChild(t);
    row.appendChild(msg);
    feed.insertBefore(row, feed.firstChild);
  };
})();

(function () {
  var seq = "";
  var help = document.getElementById("keys");
  document.addEventListener("keydown", function (e) {
    if (e.target && e.target.matches && e.target.matches("input, textarea, select")) return;
    if (e.key === "?" || (e.key === "/" && e.shiftKey)) {
      if (help && help.showModal) help.showModal();
      return;
    }
    if (e.key === "Escape" && help && help.open) { help.close(); return; }
    if (e.key === "/") {
      var s = document.querySelector("[data-search]");
      if (s) { e.preventDefault(); s.focus(); }
      return;
    }
    var go = { d: "/admin", a: "/admin/accounts", r: "/admin/routes", t: "/admin/targets", l: "/admin/deliveries", s: "/admin/settings", u: "/admin/audit" };
    if (e.key === "g") { seq = "g"; return; }
    if (seq === "g" && go[e.key]) { location.href = go[e.key]; }
    seq = "";
  });
})();

(function () {
  function csrf() { return document.body.getAttribute("data-csrf") || ""; }

  function fieldRoot(el) {
    return (el && el.closest && (el.closest(".field") || el.closest("label.check") || el.parentElement)) || el;
  }

  function clearError(el) {
    if (!el) return;
    var root = fieldRoot(el);
    if (root) root.classList.remove("is-invalid");
    el.removeAttribute("aria-invalid");
    var err = root && root.querySelector && root.querySelector(".field-error");
    if (err) err.remove();
  }

  function showError(el, msg) {
    if (!el) return;
    clearError(el);
    var root = fieldRoot(el);
    if (root) root.classList.add("is-invalid");
    el.setAttribute("aria-invalid", "true");
    var p = document.createElement("p");
    p.className = "field-error";
    p.textContent = msg;
    if (root) root.appendChild(p);
  }

  function snapshot(el) {
    if (!el || el.type === "file") return;
    el.setAttribute("data-last", el.type === "checkbox" || el.type === "radio" ? (el.checked ? "1" : "0") : el.value);
  }

  function revert(el) {
    if (!el || !el.hasAttribute("data-last")) return;
    var last = el.getAttribute("data-last");
    if (el.type === "checkbox" || el.type === "radio") el.checked = last === "1";
    else el.value = last;
  }

  function save(form, trigger) {
    var url = form.getAttribute("data-autosave");
    if (!url) return Promise.resolve();
    if (save.busy) {
      save.queued = { form: form, trigger: trigger };
      return save.busy;
    }
    var fd = new FormData(form);
    if (!fd.get("csrf")) fd.set("csrf", csrf());
    save.busy = fetch(url, {
      method: "POST",
      body: fd,
      credentials: "same-origin",
      headers: { "Accept": "application/json", "X-Requested-With": "fetch" }
    }).then(function (r) {
      return r.json().then(function (j) { return { r: r, j: j }; }, function () { return { r: r, j: null }; });
    }).then(function (x) {
      var j = x.j || {};
      if (!x.r.ok || !j.ok) {
        var msg = j.error || "Could not save.";
        var field = trigger;
        if (j.field && form.elements[j.field]) field = form.elements[j.field];
        showError(field, msg);
        if (trigger) revert(trigger);
        toast(msg, { kind: "error" });
        return;
      }
      if (trigger) { clearError(trigger); snapshot(trigger); }
      form.querySelectorAll("[data-last]").forEach(snapshot);
      toast("Saved", { kind: "success", duration: 1000 });
    }).catch(function () {
      if (trigger) revert(trigger);
      toast("Could not save.", { kind: "error" });
    }).then(function () {
      save.busy = null;
      var q = save.queued;
      save.queued = null;
      if (q) return save(q.form, q.trigger);
    });
    return save.busy;
  }
  save.busy = null;
  save.queued = null;

  window.ghookAutosave = function (form) { return save(form, null); };

  var timers = [];
  function debounce(form, el, ms) {
    var i;
    for (i = timers.length - 1; i >= 0; i--) if (timers[i].form === form) { clearTimeout(timers[i].id); timers.splice(i, 1); }
    timers.push({ form: form, id: setTimeout(function () { save(form, el); }, ms) });
  }

  document.querySelectorAll("form[data-autosave]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      var sub = e.submitter;
      if (sub && sub.getAttribute("formaction")) return;
      e.preventDefault();
    });
    form.querySelectorAll("input, textarea, select").forEach(function (el) {
      if (!el.name || el.type === "hidden" || el.type === "file" || el.type === "button" || el.type === "submit" || el.hasAttribute("data-no-autosave")) return;
      snapshot(el);
      if (el.type === "checkbox" || el.type === "radio" || el.tagName === "SELECT") {
        el.addEventListener("change", function () { debounce(form, el, 100); });
        return;
      }
      el.addEventListener("blur", function () {
        if (el.value === el.getAttribute("data-last")) return;
        debounce(form, el, 200);
      });
      el.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && el.tagName !== "TEXTAREA") {
          e.preventDefault();
          el.blur();
        }
      });
    });
  });

  document.querySelectorAll("form[data-google-consent]").forEach(function (form) {
    form.querySelectorAll("input[type=checkbox]").forEach(function (el) {
      el.addEventListener("change", function () { form.submit(); });
    });
  });
})();

// Route list: each filter value is a chip; click to edit it in place, "+ add" appends one.
// Enter or blur saves the whole field through /admin/routes/field and redraws it as stored
// (sorted, deduped). Escape cancels. An emptied value is removed.
(function () {
  var table = document.querySelector("[data-field-url]");
  if (!table) return;
  var url = table.getAttribute("data-field-url");
  var KEEP = 3;

  function values(sec, skip) {
    var out = [];
    sec.querySelectorAll(".mvals li").forEach(function (li) {
      if (li === skip || li.classList.contains("addli")) return;
      var b = li.querySelector("[data-edit]");
      if (b) out.push(b.textContent);
    });
    return out;
  }

  function chip(sec, v, i) {
    var li = document.createElement("li");
    if (i >= KEEP) li.className = "extra";
    var b = document.createElement("button");
    b.type = "button";
    b.className = "mval" + (sec.getAttribute("data-kind") === "regex" ? " re" : "");
    b.setAttribute("data-edit", "");
    b.title = v;
    b.textContent = v;
    li.appendChild(b);
    return li;
  }

  function draw(sec, vals) {
    var ul = sec.querySelector(".mvals");
    var add = ul.querySelector(".addli");
    ul.querySelectorAll("li:not(.addli)").forEach(function (li) { li.remove(); });
    vals.forEach(function (v, i) { ul.insertBefore(chip(sec, v, i), add); });
    sec.classList.toggle("any", vals.length > 1);
    var head = sec.querySelector(".msec-head");
    var op = head.querySelector(".msec-op");
    if (vals.length > 1) {
      if (!op) { op = document.createElement("span"); op.className = "msec-op"; op.title = "Any one of these matches"; head.appendChild(op); }
      op.textContent = "any of " + vals.length;
    } else if (op) op.remove();
    recount(sec.closest("[data-match]"));
  }

  function recount(box) {
    var hidden = 0;
    box.querySelectorAll(".msec").forEach(function (sec) {
      var n = sec.querySelectorAll(".mvals li:not(.addli)").length;
      if (n > KEEP) hidden += n - KEEP;
    });
    var tw = box.querySelector("[data-twistie]");
    if (!tw) {
      if (!hidden) return;
      tw = document.createElement("button");
      tw.type = "button";
      tw.className = "twistie";
      tw.setAttribute("data-twistie", "");
      tw.setAttribute("aria-expanded", box.classList.contains("collapsed") ? "false" : "true");
      tw.innerHTML = '<span class="tw-icon" aria-hidden="true"></span><span data-twistie-text></span>';
      box.appendChild(tw);
    }
    tw.hidden = !hidden;
    tw.setAttribute("data-more", hidden);
    label(box, tw);
  }

  function label(box, tw) {
    var open = !box.classList.contains("collapsed");
    tw.setAttribute("aria-expanded", open ? "true" : "false");
    tw.querySelector("[data-twistie-text]").textContent = open ? "Show less" : tw.getAttribute("data-more") + " more";
  }

  function commit(sec, li, input, original) {
    if (input.getAttribute("data-done")) return;
    input.setAttribute("data-done", "1");
    var v = input.value.trim();
    if (v === (original || "")) { restore(sec, li, original); return; }
    var others = values(sec, li);
    var vals = v ? others.concat([v]) : others;
    var before = original === null ? others : others.concat([original]);
    var fd = new FormData();
    fd.set("csrf", document.body.getAttribute("data-csrf") || "");
    fd.set("id", sec.closest("[data-match]").getAttribute("data-match"));
    fd.set("field", sec.getAttribute("data-field"));
    fd.set("value", vals.join("\n"));
    input.classList.add("busy");
    input.disabled = true;
    fetch(url, { method: "POST", body: fd, credentials: "same-origin", headers: { "Accept": "application/json", "X-Requested-With": "fetch" } })
      .then(function (r) { return r.json().then(function (j) { return { r: r, j: j }; }, function () { return { r: r, j: {} }; }); })
      .then(function (x) {
        if (!x.r.ok || !x.j.ok) throw new Error(x.j.error || "Could not save.");
        var got = x.j.values || [];
        // the last value of a field went: the cell's sections change, so redraw the page
        if (!got.length) { location.reload(); return; }
        draw(sec, got);
        toast("Saved", { kind: "success", duration: 1000 });
        var add = original === null && sec.querySelector("[data-add]");
        if (add) add.focus();
      })
      .catch(function (err) {
        toast(err.message || "Could not save.", { kind: "error" });
        draw(sec, before);
      });
  }

  function restore(sec, li, original) {
    if (original === null) { li.remove(); var a = sec.querySelector("[data-add]"); if (a) a.focus(); return; }
    var b = chip(sec, original, 0).firstChild;
    li.innerHTML = "";
    li.appendChild(b);
    b.focus();
  }

  function edit(sec, li, original) {
    var input = document.createElement("input");
    input.type = "text";
    input.className = "mval-input";
    input.value = original || "";
    input.setAttribute("aria-label", sec.getAttribute("aria-label") + (original === null ? ", new value" : ""));
    input.setAttribute("spellcheck", "false");
    input.setAttribute("autocomplete", "off");
    li.innerHTML = "";
    li.appendChild(input);
    input.focus();
    if (original) input.select();
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") { e.preventDefault(); commit(sec, li, input, original); }
      else if (e.key === "Escape") { e.preventDefault(); input.setAttribute("data-done", "1"); restore(sec, li, original); }
    });
    input.addEventListener("blur", function () { commit(sec, li, input, original); });
  }

  table.addEventListener("click", function (e) {
    var b = e.target.closest("[data-edit]");
    if (b) {
      var sec = b.closest(".msec");
      edit(sec, b.closest("li"), b.textContent);
      return;
    }
    var a = e.target.closest("[data-add]");
    if (a) {
      var sec2 = a.closest(".msec");
      var box = sec2.closest("[data-match]");
      box.classList.remove("collapsed");
      var tw = box.querySelector("[data-twistie]");
      if (tw) label(box, tw);
      var li = document.createElement("li");
      sec2.querySelector(".mvals").insertBefore(li, a.closest("li"));
      edit(sec2, li, null);
      return;
    }
    var t = e.target.closest("[data-twistie]");
    if (t) {
      var bx = t.closest("[data-match]");
      bx.classList.toggle("collapsed");
      label(bx, t);
      try {
        var k = "ghook.match.open." + bx.getAttribute("data-match");
        if (bx.classList.contains("collapsed")) localStorage.removeItem(k); else localStorage.setItem(k, "1");
      } catch (err) {}
    }
  });

  table.querySelectorAll("[data-match]").forEach(function (box) {
    var tw = box.querySelector("[data-twistie]");
    if (!tw) return;
    try { if (localStorage.getItem("ghook.match.open." + box.getAttribute("data-match"))) box.classList.remove("collapsed"); } catch (err) {}
    label(box, tw);
  });
})();

// GET filter forms apply as soon as a select changes.
document.querySelectorAll("form[data-autosubmit]").forEach(function (f) {
  f.querySelectorAll("select").forEach(function (el) {
    el.addEventListener("change", function () { f.submit(); });
  });
});
