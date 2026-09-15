(function () {
  var palette = document.getElementById("cmd-palette");
  if (!palette) return;

  var input = document.getElementById("palette-input");
  var results = document.getElementById("palette-results");
  var backdrop = document.querySelector("[data-palette-backdrop]");
  var staticRows = Array.prototype.slice.call(results.querySelectorAll(".palette-row"));
  var commands = staticRows.map(function (el) {
    return {
      cmd: el.getAttribute("data-cmd"),
      desc: el.getAttribute("data-desc"),
      href: el.getAttribute("href"),
      action: el.getAttribute("data-action"),
      color: el.style.color,
    };
  });

  var searchIndex = null;
  var selected = -1;
  var lastTrigger = null;

  function statusModeEl() {
    var buf = document.querySelector(".buf");
    return buf ? buf.querySelector(".statusline .mode") : null;
  }

  var savedMode = null;

  function isOpen() {
    return document.body.getAttribute("data-palette-open") === "true";
  }

  function render(rows) {
    results.innerHTML = "";
    rows.forEach(function (r, i) {
      var a = document.createElement(r.href ? "a" : "div");
      a.className = "palette-row";
      a.setAttribute("role", "option");
      a.style.color = r.color || "";
      if (r.href) a.href = r.href;
      if (r.action) a.setAttribute("data-action", r.action);
      var cmd = document.createElement("span");
      cmd.className = "cmd";
      cmd.style.width = "76px";
      cmd.style.flex = "none";
      cmd.textContent = r.cmd;
      var desc = document.createElement("span");
      desc.className = "desc";
      desc.textContent = r.desc;
      a.appendChild(cmd);
      a.appendChild(desc);
      a.addEventListener("click", function (e) {
        onSelectRow(e, r);
      });
      results.appendChild(a);
    });
    selected = rows.length ? 0 : -1;
    updateSelection();
  }

  function updateSelection() {
    var rows = results.querySelectorAll(".palette-row");
    rows.forEach(function (el, i) {
      el.classList.toggle("is-selected", i === selected);
    });
    if (selected >= 0 && rows[selected]) {
      rows[selected].scrollIntoView({ block: "nearest" });
    }
  }

  function onSelectRow(e, r) {
    if (e) e.preventDefault();
    if (r.action === "theme") {
      if (window.__theme) window.__theme.toggle();
      close();
    } else if (r.href) {
      close();
      window.location.assign(r.href);
    } else {
      close();
    }
  }

  function fuzzyScore(needle, haystack) {
    needle = needle.toLowerCase();
    haystack = haystack.toLowerCase();
    var hi = 0;
    for (var ni = 0; ni < needle.length; ni++) {
      hi = haystack.indexOf(needle[ni], hi);
      if (hi === -1) return -1;
      hi++;
    }
    return 1;
  }

  function loadSearchIndex(cb) {
    if (searchIndex) return cb(searchIndex);
    fetch("/search.json")
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        searchIndex = data;
        cb(data);
      })
      .catch(function () {
        cb([]);
      });
  }

  function filter(query) {
    if (query.indexOf("search ") === 0 || query.indexOf("/") === 0) {
      var term = query.replace(/^search /, "").replace(/^\//, "");
      if (!term) {
        render([]);
        return;
      }
      loadSearchIndex(function (data) {
        var matches = data
          .filter(function (d) {
            return fuzzyScore(term, d.title + " " + d.excerpt) !== -1;
          })
          .slice(0, 12)
          .map(function (d) {
            return { cmd: d.category, desc: d.title, href: d.url, color: "" };
          });
        render(matches);
      });
      return;
    }
    var q = query.trim().replace(/^:/, "").toLowerCase();
    var matches = commands.filter(function (c) {
      return !q || c.cmd.toLowerCase().indexOf(q) !== -1 || c.desc.toLowerCase().indexOf(q) !== -1;
    });
    render(matches);
  }

  function open(prefill, trigger) {
    lastTrigger = trigger || document.activeElement;
    document.body.setAttribute("data-palette-open", "true");
    input.value = prefill || "";
    filter(input.value);
    var mode = statusModeEl();
    if (mode && !savedMode) {
      savedMode = { text: mode.textContent, style: mode.getAttribute("style") };
    }
    if (mode) {
      mode.textContent = "COMMAND";
      mode.style.setProperty("--mode", "var(--mode-command)");
    }
    requestAnimationFrame(function () {
      input.focus();
      input.setSelectionRange(input.value.length, input.value.length);
    });
  }

  function close() {
    document.body.setAttribute("data-palette-open", "false");
    var mode = statusModeEl();
    if (mode && savedMode) {
      mode.textContent = savedMode.text;
      if (savedMode.style) mode.setAttribute("style", savedMode.style);
      else mode.removeAttribute("style");
    }
    savedMode = null;
    if (lastTrigger && lastTrigger.focus) lastTrigger.focus();
  }

  document.querySelectorAll(".js-palette-open").forEach(function (btn) {
    btn.addEventListener("click", function () {
      open("", btn);
    });
  });

  if (backdrop) {
    backdrop.addEventListener("click", close);
  }

  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    var typing = tag === "INPUT" || tag === "TEXTAREA" || document.activeElement.isContentEditable;

    if (!isOpen()) {
      if (e.key === ":" && !typing) {
        e.preventDefault();
        open("");
      } else if (e.key === "/" && !typing) {
        e.preventDefault();
        open("search ");
      }
      return;
    }

    if (e.key === "Escape") {
      close();
    } else if (e.key === "ArrowDown" || (e.ctrlKey && e.key === "n")) {
      e.preventDefault();
      var rows = results.querySelectorAll(".palette-row");
      if (rows.length) {
        selected = (selected + 1) % rows.length;
        updateSelection();
      }
    } else if (e.key === "ArrowUp" || (e.ctrlKey && e.key === "p")) {
      e.preventDefault();
      var rows2 = results.querySelectorAll(".palette-row");
      if (rows2.length) {
        selected = (selected - 1 + rows2.length) % rows2.length;
        updateSelection();
      }
    } else if (e.key === "Enter") {
      e.preventDefault();
      var rows3 = results.querySelectorAll(".palette-row");
      if (selected >= 0 && rows3[selected]) rows3[selected].click();
    } else if (e.key === "Tab") {
      var rows4 = results.querySelectorAll(".palette-row");
      if (rows4.length) {
        e.preventDefault();
        if (rows4.length === 1) {
          selected = 0;
        } else {
          selected = (selected + (e.shiftKey ? -1 : 1) + rows4.length) % rows4.length;
        }
        updateSelection();
        var cmdText = rows4[selected].querySelector(".cmd");
        if (cmdText) {
          input.value = cmdText.textContent + " ";
          filter(input.value);
          input.focus();
          input.setSelectionRange(input.value.length, input.value.length);
        }
      }
    }
  });

  input.addEventListener("input", function () {
    filter(input.value);
  });

  // mobile swipe-down to close
  var touchStartY = null;
  palette.addEventListener(
    "touchstart",
    function (e) {
      touchStartY = e.touches[0].clientY;
    },
    { passive: true }
  );
  palette.addEventListener(
    "touchend",
    function (e) {
      if (touchStartY === null) return;
      var dy = e.changedTouches[0].clientY - touchStartY;
      if (dy > 60) close();
      touchStartY = null;
    },
    { passive: true }
  );

  window.__palette = { open: open, close: close };
})();
