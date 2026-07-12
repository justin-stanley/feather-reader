/* FeatherReader — a tiny, dependency-free keyboard handler.
 *
 * Reading is a keyboard flow (design §3): j/k move between entries, o/Enter
 * open, m toggle-read, s star, r refresh, A mark-all-read, g g / G top/bottom,
 * ? help. No framework — plain DOM. Works on both the list view (an
 * `#entry-list` of `.entry-row`s) and the single-article view (`.article`).
 *
 * The handler is intentionally conservative: it never swallows keys while the
 * user is typing in a field, and every shortcut maps onto a link or form that
 * also works by mouse / with JS disabled — this only accelerates, it is never
 * the only way to do a thing.
 */
(function () {
  "use strict";

  // Don't hijack keys while typing in an input, textarea, select, or anything
  // contenteditable — the reader must never eat what you're typing.
  function isTyping(el) {
    if (!el) return false;
    var tag = (el.tagName || "").toLowerCase();
    return (
      tag === "input" ||
      tag === "textarea" ||
      tag === "select" ||
      el.isContentEditable === true
    );
  }

  function rows() {
    return Array.prototype.slice.call(
      document.querySelectorAll("#entry-list .entry-row")
    );
  }

  var CURSOR_CLASS = "is-cursor";

  function currentIndex(list) {
    for (var i = 0; i < list.length; i++) {
      if (list[i].classList.contains(CURSOR_CLASS)) return i;
    }
    return -1;
  }

  function focusRow(list, idx) {
    if (!list.length) return;
    if (idx < 0) idx = 0;
    if (idx >= list.length) idx = list.length - 1;
    list.forEach(function (r) {
      r.classList.remove(CURSOR_CLASS);
    });
    var row = list[idx];
    row.classList.add(CURSOR_CLASS);
    // Keep the cursor comfortably in view without yanking the whole page.
    var rect = row.getBoundingClientRect();
    if (rect.top < 80 || rect.bottom > window.innerHeight - 40) {
      row.scrollIntoView({ block: "center", behavior: "smooth" });
    }
    return row;
  }

  function move(delta) {
    var list = rows();
    if (!list.length) return;
    var idx = currentIndex(list);
    if (idx === -1) {
      idx = delta > 0 ? 0 : list.length - 1;
    } else {
      idx += delta;
    }
    focusRow(list, idx);
  }

  function activeRow() {
    var list = rows();
    var idx = currentIndex(list);
    return idx === -1 ? null : list[idx];
  }

  // Open the entry under the cursor (list view) — follow its reader link.
  function openCurrent() {
    var row = activeRow();
    if (!row) return;
    var link = row.querySelector(".entry-link");
    if (link) window.location.href = link.getAttribute("href");
  }

  // Submit a named action form (mark-read / star) on the current row, or on the
  // article view where there is exactly one such form.
  function submitAction(selector) {
    var scope = activeRow();
    if (!scope) {
      // Article view: the whole page is the scope.
      scope = document.querySelector(".article");
    }
    if (!scope) return;
    var form = scope.querySelector(selector);
    if (!form) return;
    // Prefer htmx's programmatic trigger so we get the in-place swap; fall back
    // to a native submit when htmx isn't loaded.
    if (form.requestSubmit) {
      form.requestSubmit();
    } else {
      form.submit();
    }
  }

  function markAllRead() {
    var form = document.querySelector("#mark-all-form");
    if (form && form.requestSubmit) {
      form.requestSubmit();
    } else if (form) {
      form.submit();
    }
  }

  function refresh() {
    window.location.reload();
  }

  function toggleHelp() {
    var help = document.querySelector("#kbd-help");
    if (help) help.toggleAttribute("open");
  }

  var lastG = 0;

  document.addEventListener("keydown", function (ev) {
    if (ev.defaultPrevented) return;
    if (ev.metaKey || ev.ctrlKey || ev.altKey) return;
    if (isTyping(ev.target)) return;

    var k = ev.key;

    // g g → top, G → bottom.
    if (k === "g") {
      var now = Date.now();
      if (now - lastG < 500) {
        var list = rows();
        focusRow(list, 0);
        lastG = 0;
      } else {
        lastG = now;
      }
      return;
    }
    if (k === "G") {
      var all = rows();
      focusRow(all, all.length - 1);
      ev.preventDefault();
      return;
    }

    switch (k) {
      case "j":
        move(1);
        ev.preventDefault();
        break;
      case "k":
        move(-1);
        ev.preventDefault();
        break;
      case "o":
      case "Enter":
        // On the list, open the cursored entry. In a field this never fires.
        if (rows().length) {
          openCurrent();
          ev.preventDefault();
        }
        break;
      case "m":
        submitAction(".mark-read-form");
        ev.preventDefault();
        break;
      case "s":
        submitAction(".star-form");
        ev.preventDefault();
        break;
      case "A":
        markAllRead();
        ev.preventDefault();
        break;
      case "r":
        refresh();
        ev.preventDefault();
        break;
      case "u":
        // Back to the unread list from an article.
        if (document.querySelector(".article")) {
          window.location.href = "/";
          ev.preventDefault();
        }
        break;
      case "?":
        toggleHelp();
        ev.preventDefault();
        break;
      default:
        break;
    }
  });

  // Put the cursor on the first row on load so j/k has an anchor.
  document.addEventListener("DOMContentLoaded", function () {
    var list = rows();
    if (list.length && currentIndex(list) === -1) {
      list[0].classList.add(CURSOR_CLASS);
    }
  });
})();
