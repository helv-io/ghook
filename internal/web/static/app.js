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

function toast(msg, kind) {
  var host = document.querySelector(".toasts");
  if (!host) {
    host = document.createElement("div");
    host.className = "toasts";
    document.body.appendChild(host);
  }
  var el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(function () { el.classList.add("gone"); setTimeout(function () { el.remove(); }, 300); }, 4000);
}

document.querySelectorAll(".toast").forEach(function (el) {
  setTimeout(function () { el.classList.add("gone"); }, 4000);
  el.addEventListener("click", function () { el.remove(); });
});

document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy-text]");
  if (!b) return;
  var text = b.getAttribute("data-copy-text");
  var done = function () { toast("Copied", "ok"); };
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
    if (parts.length < 2) { toast("Paste the URL and the key, separated by a space", "warn"); return; }
    var form = box.closest("form");
    form.querySelector("[name=url]").value = parts[0];
    form.querySelector("[name=secret]").value = parts.slice(1).join(" ");
    var mode = form.querySelector("[name=auth_mode]");
    if (mode) mode.value = "bearer";
    toast("URL and key filled in. Save the target.", "ok");
  });
})();

(function () {
  var table = document.querySelector("[data-reorder]");
  if (!table) return;
  var drag = null;
  function ids() {
    return [].map.call(table.querySelectorAll("tbody tr[data-id]"), function (tr) { return tr.getAttribute("data-id"); });
  }
  function save() {
    var fd = new FormData();
    fd.set("csrf", document.body.getAttribute("data-csrf") || "");
    ids().forEach(function (id) { fd.append("id", id); });
    fetch(table.getAttribute("data-reorder"), { method: "POST", body: fd, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("save"); toast("Order saved", "ok"); })
      .catch(function () { toast("Could not save the order", "bad"); });
  }
  table.addEventListener("dragstart", function (e) {
    var tr = e.target.closest("tr[data-id]");
    if (!tr) return;
    drag = tr;
    tr.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", tr.getAttribute("data-id"));
  });
  table.addEventListener("dragend", function () { if (drag) drag.classList.remove("dragging"); drag = null; });
  table.addEventListener("dragover", function (e) {
    var tr = e.target.closest("tr[data-id]");
    if (!tr || !drag || tr === drag) return;
    e.preventDefault();
    var after = e.clientY > tr.getBoundingClientRect().top + tr.getBoundingClientRect().height / 2;
    tr.parentNode.insertBefore(drag, after ? tr.nextSibling : tr);
  });
  table.addEventListener("drop", function (e) { e.preventDefault(); save(); });
  document.addEventListener("keydown", function (e) {
    if (!e.altKey || (e.key !== "ArrowUp" && e.key !== "ArrowDown")) return;
    var tr = document.activeElement && document.activeElement.closest ? document.activeElement.closest("tr[data-id]") : null;
    if (!tr || !table.contains(tr)) return;
    e.preventDefault();
    var sib = e.key === "ArrowUp" ? tr.previousElementSibling : tr.nextElementSibling;
    if (!sib || !sib.getAttribute || !sib.getAttribute("data-id")) return;
    if (e.key === "ArrowUp") tr.parentNode.insertBefore(tr, sib);
    else tr.parentNode.insertBefore(sib, tr);
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
