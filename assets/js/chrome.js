(function () {
  // measure the real statusline height (fixed-positioned, so it's out of
  // flow) and publish it as a CSS var everything else reads from, instead
  // of guessing a hardcoded px offset. Recomputed on resize and via
  // ResizeObserver so it stays correct across breakpoint/orientation changes.
  function trackHeight(el, varName) {
    if (!el) return;
    function update() {
      var h = el.getBoundingClientRect().height;
      document.documentElement.style.setProperty(varName, h + "px");
    }
    update();
    window.addEventListener("resize", update);
    if (window.ResizeObserver) new ResizeObserver(update).observe(el);
  }

  trackHeight(document.querySelector(".statusline"), "--statusline-h");

  // scroll progress + ln/pct on post pages, plus TOC scroll-spy
  var isPost = document.querySelector(".page-post");
  if (isPost) {
    var fill = document.getElementById("progress-fill");
    var lnCell = document.getElementById("status-ln");
    var pctCell = document.getElementById("status-pct");
    var totalMatch = lnCell && lnCell.textContent.match(/\/(\d+)/);
    var total = totalMatch ? parseInt(totalMatch[1], 10) : 0;

    var headings = Array.prototype.slice.call(document.querySelectorAll(".post-body h2[id]"));
    var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a[href^='#']"));

    function updateTocSpy() {
      if (!headings.length || !tocLinks.length) return;
      var current = null;
      for (var i = 0; i < headings.length; i++) {
        if (headings[i].getBoundingClientRect().top <= 96) current = headings[i];
      }
      tocLinks.forEach(function (a) {
        var match = current && a.getAttribute("href") === "#" + current.id;
        a.classList.toggle("is-current", !!match);
      });
    }

    function onScroll() {
      var doc = document.documentElement;
      var scrollable = doc.scrollHeight - doc.clientHeight;
      var pct = scrollable > 0 ? Math.min(1, Math.max(0, doc.scrollTop / scrollable)) : 0;
      if (fill) fill.style.width = pct * 100 + "%";
      if (pctCell) pctCell.textContent = Math.round(pct * 100) + "%";
      if (lnCell && total) lnCell.textContent = "ln " + Math.max(1, Math.round(pct * total)) + "/" + total;
      updateTocSpy();
    }

    document.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  // netrw-style cursor on the /posts/ listing: j/k move a highlighted row
  // instead of scrolling the page, Enter opens it. Desktop only — on mobile
  // there's no keyboard driving this, so plain touch-scroll stays untouched.
  var netrwList = document.querySelector(".netrw-list");
  var netrwEntries = netrwList ? Array.prototype.slice.call(netrwList.querySelectorAll(".netrw-entry")) : [];
  var netrwIndex = 0;
  var isDesktop = window.matchMedia("(min-width: 900px)").matches;

  function netrwActive() {
    return netrwEntries.length > 0 && window.matchMedia("(min-width: 900px)").matches;
  }

  function setNetrwCursor(i) {
    netrwIndex = Math.max(0, Math.min(netrwEntries.length - 1, i));
    netrwEntries.forEach(function (el, idx) {
      el.classList.toggle("is-cursor", idx === netrwIndex);
    });
    netrwEntries[netrwIndex].scrollIntoView({ block: "nearest" });
  }

  if (netrwEntries.length && isDesktop) {
    setNetrwCursor(0);
  }

  // neovim-style buffer navigation: h/j/k/l scroll, gg/G jump to top/bottom,
  // Ctrl-U/Ctrl-D half-page scroll. Skipped while typing or while the
  // command palette is open.
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var STEP = 90;

  // rAF-driven smooth scroll: repeated taps add to one running target
  // instead of each keydown starting its own competing native smooth-scroll
  // animation (which is what made rapid j/j/j presses feel choppy/janky).
  var scrollTarget = { x: window.scrollX, y: window.scrollY };
  var scrollRaf = null;

  function stepScroll() {
    var dx = scrollTarget.x - window.scrollX;
    var dy = scrollTarget.y - window.scrollY;
    if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5) {
      window.scrollTo(scrollTarget.x, scrollTarget.y);
      scrollRaf = null;
      return;
    }
    window.scrollBy(dx * 0.22, dy * 0.22);
    scrollRaf = requestAnimationFrame(stepScroll);
  }

  function maxScroll() {
    var doc = document.documentElement;
    return { x: doc.scrollWidth - doc.clientWidth, y: doc.scrollHeight - doc.clientHeight };
  }

  function smoothScrollBy(dx, dy) {
    if (reduceMotion) {
      window.scrollBy(dx, dy);
      scrollTarget.x = window.scrollX;
      scrollTarget.y = window.scrollY;
      return;
    }
    var bounds = maxScroll();
    scrollTarget.x = Math.max(0, Math.min(bounds.x, scrollTarget.x + dx));
    scrollTarget.y = Math.max(0, Math.min(bounds.y, scrollTarget.y + dy));
    if (!scrollRaf) scrollRaf = requestAnimationFrame(stepScroll);
  }

  function smoothScrollTo(x, y) {
    scrollTarget.x = x;
    scrollTarget.y = y;
    if (reduceMotion) {
      window.scrollTo(x, y);
    } else if (!scrollRaf) {
      scrollRaf = requestAnimationFrame(stepScroll);
    }
  }

  // a manual wheel/touch scroll should reset the target under the cursor's
  // fingers, not fight the in-flight animation on the next keypress
  window.addEventListener(
    "wheel",
    function () {
      scrollTarget.x = window.scrollX;
      scrollTarget.y = window.scrollY;
    },
    { passive: true }
  );

  var lastG = 0;

  document.addEventListener("keydown", function (e) {
    var tag = (document.activeElement && document.activeElement.tagName) || "";
    var typing = tag === "INPUT" || tag === "TEXTAREA" || document.activeElement.isContentEditable;
    if (typing) return;
    if (document.body.getAttribute("data-palette-open") === "true") return;

    if (netrwActive() && (e.key === "j" || e.key === "k")) {
      e.preventDefault();
      setNetrwCursor(netrwIndex + (e.key === "j" ? 1 : -1));
      return;
    }
    if (netrwActive() && e.key === "Enter") {
      e.preventDefault();
      window.location.assign(netrwEntries[netrwIndex].getAttribute("href"));
      return;
    }
    if (netrwActive() && e.key === "G") {
      setNetrwCursor(netrwEntries.length - 1);
      return;
    }

    if (e.ctrlKey && (e.key === "d" || e.key === "D")) {
      e.preventDefault();
      smoothScrollBy(0, window.innerHeight / 2);
    } else if (e.ctrlKey && (e.key === "u" || e.key === "U")) {
      e.preventDefault();
      smoothScrollBy(0, -window.innerHeight / 2);
    } else if (e.ctrlKey || e.metaKey || e.altKey) {
      return;
    } else if (e.key === "j") {
      smoothScrollBy(0, STEP);
    } else if (e.key === "k") {
      smoothScrollBy(0, -STEP);
    } else if (e.key === "h") {
      smoothScrollBy(-STEP, 0);
    } else if (e.key === "l") {
      smoothScrollBy(STEP, 0);
    } else if (e.key === "G") {
      smoothScrollTo(scrollTarget.x, maxScroll().y);
    } else if (e.key === "g") {
      var now = Date.now();
      if (now - lastG < 500) {
        if (netrwActive()) setNetrwCursor(0);
        else smoothScrollTo(scrollTarget.x, 0);
        lastG = 0;
      } else {
        lastG = now;
      }
    }
  });
})();
