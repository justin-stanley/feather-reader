/* FeatherReader — keyboard.js
 * Progressive enhancement only: the app is fully usable without this file.
 * 1. Mobile drawer toggle.
 * 2. Keyboard shortcuts: j/k move cursor, o open, m read, s star,
 *    A mark-all-read, ? shortcuts overlay, Esc close.
 *
 * In the real app the shortcuts drive the EXISTING htmx controls (they click
 * the real buttons) rather than toggling demo classes, so every action goes
 * through the same server endpoints as a mouse click.
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

  /* Click the first matching real control inside `root` (the htmx button /
   * form submit that owns the endpoint) — never a demo class-toggle. */
  function trigger(root, selector) {
    if (!root) return;
    var el = root.querySelector(selector);
    if (el) el.click();
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
        /* Reader view: open the original. List view: open the cursored entry. */
        var actionOpen = document.querySelector(".actionbar-open");
        if (actionOpen) { actionOpen.click(); break; }
        trigger(cursorRow(), ".entry-main");
        break;
      }
      case "m": {
        /* Reader action bar takes precedence; else the cursored row's
         * mark-read control. Both POST /entries/:id/read. */
        var actionRead = document.querySelector(".actionbar-read");
        if (actionRead) { actionRead.click(); break; }
        trigger(cursorRow(), ".mark-read");
        break;
      }
      case "s": {
        var actionStar = document.querySelector(".actionbar-star");
        if (actionStar) { actionStar.click(); break; }
        trigger(cursorRow(), ".star-btn");
        break;
      }
      case "A": {
        /* Mark all read — the header / topbar control. */
        trigger(document, ".js-mark-all");
        break;
      }
      case "?": setOverlay(!(overlay && overlay.classList.contains("is-open"))); break;
      case "Escape": setOverlay(false); setDrawer(false); break;
      default: return;
    }
    e.preventDefault();
  });
})();
