/* FeatherReader — keyboard.js
 * Progressive enhancement only: the app is fully usable without this file.
 * 1. Mobile drawer toggle.
 * 2. Keyboard shortcuts: j/k move cursor, o open, m read, s star,
 *    A mark-all-read, ? shortcuts overlay, Esc close.
 * 3. Boosted navigation (#345): the shell's links and forms carry
 *    hx-boost, so htmx fetches the next page and swaps the body instead of
 *    the browser reloading it. Every listener here is therefore DELEGATED
 *    (looked up at event time), since a swap replaces the elements.
 * 4. The rail keeps its scroll position from page to page, swapped or
 *    reloaded, so picking a feed far down the list, or marking all read,
 *    does not throw the reader back to the top of it (#345, #347).
 *
 * In the real app the shortcuts drive the EXISTING htmx controls (they click
 * the real buttons) rather than toggling demo classes, so every action goes
 * through the same server endpoints as a mouse click.
 */
(function () {
  "use strict";

  function byId(id) { return document.getElementById(id); }

  /* ---- drawer -------------------------------------------------------- */
  function setDrawer(open) {
    var shell = byId("shell");
    if (!shell) return;
    shell.classList.toggle("rail-open", open);
    var toggle = byId("rail-toggle");
    if (toggle) toggle.setAttribute("aria-expanded", String(open));
  }

  /* ---- shortcuts overlay ---------------------------------------------- */
  function overlayEl() { return byId("kbd-overlay"); }
  function setOverlay(open) {
    var overlay = overlayEl();
    if (overlay) overlay.classList.toggle("is-open", open);
  }

  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!(t instanceof Element)) return;
    if (t.closest("#rail-toggle")) setDrawer(true);
    else if (t.closest("#rail-close") || t.closest("#scrim")) setDrawer(false);
    else if (t.closest("#kbd-close") || t === overlayEl()) setOverlay(false);
  });

  /* ---- rail scroll position ------------------------------------------- */
  /* A swap or a reload rebuilds the rail scrolled to the top. The position
   * is carried across a boosted swap in memory, and across a real page load
   * in sessionStorage (per tab). Storage can be unavailable (private modes,
   * blocked site data): then a reload starts the rail at the top, as before. */
  var RAIL_KEY = "featherreader.railScroll";
  var railTop = 0;
  function railEl() { return document.querySelector(".rail-scroll"); }
  function restoreRail(top) {
    var rail = railEl();
    if (rail && top > 0) rail.scrollTop = top;
  }
  try {
    restoreRail(parseInt(sessionStorage.getItem(RAIL_KEY), 10));
  } catch (_) { /* no storage: start at the top */ }
  window.addEventListener("pagehide", function () {
    var rail = railEl();
    if (!rail) return;
    try {
      sessionStorage.setItem(RAIL_KEY, String(rail.scrollTop));
    } catch (_) { /* no storage: nothing to keep */ }
  });

  /* ---- boosted navigation (#345) -------------------------------------- */
  document.addEventListener("htmx:beforeSwap", function (e) {
    if (!e.detail.boosted) return;
    /* An error page is still a page: show it, as a reload would have,
     * rather than leave the click looking ignored. */
    if (e.detail.xhr && e.detail.xhr.status >= 400) {
      e.detail.shouldSwap = true;
      e.detail.isError = false;
    }
    var rail = railEl();
    railTop = rail ? rail.scrollTop : 0;
  });
  document.addEventListener("htmx:afterSwap", function (e) {
    if (e.detail.boosted) restoreRail(railTop);
  });
  /* No answer (offline, a dropped connection): fall back to a real
   * navigation, so the browser shows its own error instead of nothing. */
  document.addEventListener("htmx:sendError", function (e) {
    var elt = e.detail.elt;
    if (e.detail.boosted && elt instanceof HTMLAnchorElement) {
      window.location.assign(elt.href);
    }
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
      case "?": {
        var ov = overlayEl();
        setOverlay(!(ov && ov.classList.contains("is-open")));
        break;
      }
      case "Escape": setOverlay(false); setDrawer(false); break;
      default: return;
    }
    e.preventDefault();
  });
})();
