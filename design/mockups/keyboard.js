/* FeatherReader — keyboard.js
 * Progressive enhancement only: the app is fully usable without this file.
 * 1. Mobile drawer toggle.
 * 2. Keyboard shortcuts: j/k move cursor, o open, m read, s star,
 *    A mark-all-read, ? shortcuts overlay, Esc close.
 */
(function () {
  "use strict";

  /* ---- drawer -------------------------------------------------------- */
  var shell = document.getElementById("shell");
  var toggle = document.getElementById("rail-toggle");
  var close = document.getElementById("rail-close");
  var scrim = document.getElementById("scrim");

  function setDrawer(open) {
    if (!shell) return;
    shell.classList.toggle("rail-open", open);
    if (toggle) toggle.setAttribute("aria-expanded", String(open));
  }
  if (toggle) toggle.addEventListener("click", function () { setDrawer(true); });
  if (close) close.addEventListener("click", function () { setDrawer(false); });
  if (scrim) scrim.addEventListener("click", function () { setDrawer(false); });

  /* ---- shortcuts overlay ---------------------------------------------- */
  var overlay = document.getElementById("kbd-overlay");
  var overlayClose = document.getElementById("kbd-close");

  function setOverlay(open) {
    if (overlay) overlay.classList.toggle("is-open", open);
  }
  if (overlayClose) overlayClose.addEventListener("click", function () { setOverlay(false); });
  if (overlay) overlay.addEventListener("click", function (e) {
    if (e.target === overlay) setOverlay(false);
  });

  /* ---- list cursor (j / k) --------------------------------------------- */
  function rows() {
    return Array.prototype.slice.call(document.querySelectorAll(".entry"));
  }
  function cursorIndex(list) {
    return list.findIndex(function (r) { return r.classList.contains("is-cursor"); });
  }
  function moveCursor(delta) {
    var list = rows();
    if (!list.length) return;
    var i = cursorIndex(list);
    var next = Math.min(list.length - 1, Math.max(0, (i === -1 ? 0 : i + delta)));
    list.forEach(function (r) { r.classList.remove("is-cursor"); });
    list[next].classList.add("is-cursor");
    list[next].scrollIntoView({ block: "nearest" });
  }
  function cursorRow() {
    var list = rows();
    var i = cursorIndex(list);
    return i === -1 ? null : list[i];
  }

  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;

    switch (e.key) {
      case "j": moveCursor(1); break;
      case "k": moveCursor(-1); break;
      case "o":
      case "Enter": {
        var row = cursorRow();
        var link = row && row.querySelector(".entry-main");
        if (link) link.click();
        break;
      }
      case "m": {
        var r = cursorRow();
        if (r) r.classList.toggle("is-read"); /* real app: htmx POST /entries/:id/read */
        break;
      }
      case "s": {
        var c = cursorRow();
        var star = c && c.querySelector(".star-btn");
        if (star) star.setAttribute("aria-pressed",
          star.getAttribute("aria-pressed") === "true" ? "false" : "true");
        break;
      }
      case "A": {
        rows().forEach(function (r) { r.classList.add("is-read"); }); /* real app: htmx POST */
        break;
      }
      case "?": setOverlay(!(overlay && overlay.classList.contains("is-open"))); break;
      case "Escape": setOverlay(false); setDrawer(false); break;
      default: return;
    }
    e.preventDefault();
  });
})();
